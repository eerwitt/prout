param(
  [Parameter(Mandatory=$true)][string]$ProutExe,
  [string]$DistDir = ""
)

$ErrorActionPreference = "Stop"

if ($DistDir) {
  $distExe = Join-Path $DistDir "prout.exe"
  if (Test-Path $distExe) { $ProutExe = $distExe }
}
if (-not (Test-Path $ProutExe)) { throw "prout executable not found: $ProutExe" }

$root = Join-Path $env:TEMP ("prout-ctest-" + [guid]::NewGuid().ToString("N").Substring(0,8))
New-Item -ItemType Directory -Force -Path $root | Out-Null
$env:PROUT_HOME = $root
$env:PROUT_SOCKET = Join-Path $root "prout.sock"
$env:PROUT_PASSPHRASE = "test-passphrase"
$env:PROUT_MACHINE = "ctest"
$daemon = $null

function Fail([string]$Message) { throw $Message }

function Quote-Arg([string]$Value) {
  if ($null -eq $Value) { return '""' }
  if ($Value -notmatch '[\s"]') { return $Value }
  return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function Invoke-Prout {
  param([string[]]$ArgList, [int]$TimeoutSeconds = 10)
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $ProutExe
  $psi.Arguments = ($ArgList | ForEach-Object { Quote-Arg $_ }) -join ' '
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
    try { $p.Kill() } catch {}
    return [pscustomobject]@{ Code = -999; Out = $p.StandardOutput.ReadToEnd(); Err = 'timeout' }
  }
  return [pscustomobject]@{ Code = $p.ExitCode; Out = $p.StandardOutput.ReadToEnd(); Err = $p.StandardError.ReadToEnd() }
}

try {
  $r = Invoke-Prout -ArgList @('vault', 'init')
  if ($r.Code -ne 0) { Fail "vault init failed: $($r.Err)" }

  $env:PROUT_CREDENTIAL = 'inject-secret'
  $r = Invoke-Prout -ArgList @('vault', 'add', 'api', '--env', 'API_TOKEN', '--disclosure', 'inject', '--max-ttl', '120', '--max-uses', '2', '--description', 'test api token', '--guidance', 'grant concrete local test intents')
  if ($r.Code -ne 0) { Fail "vault add inject failed: $($r.Err)" }

  $env:PROUT_CREDENTIAL = 'reveal-secret'
  $r = Invoke-Prout -ArgList @('vault', 'add', 'reveal', '--env', 'REVEAL_TOKEN', '--disclosure', 'reveal', '--max-ttl', '120', '--max-uses', '1', '--description', 'test reveal token')
  if ($r.Code -ne 0) { Fail "vault add reveal failed: $($r.Err)" }
  $env:PROUT_CREDENTIAL = ''

  $r = Invoke-Prout -ArgList @('vault', 'list')
  if ($r.Code -ne 0) { Fail "vault list failed: $($r.Err)" }
  if (($r.Out + $r.Err).Contains('inject-secret') -or ($r.Out + $r.Err).Contains('reveal-secret')) { Fail 'vault list leaked a credential' }

  $daemonPsi = [System.Diagnostics.ProcessStartInfo]::new()
  $daemonPsi.FileName = $ProutExe
  $daemonPsi.Arguments = 'serve'
  $daemonPsi.UseShellExecute = $false
  $daemonPsi.RedirectStandardOutput = $true
  $daemonPsi.RedirectStandardError = $true
  $daemon = [System.Diagnostics.Process]::Start($daemonPsi)

  $ready = $false
  for ($i = 0; $i -lt 50; $i++) {
    $probe = Invoke-Prout -ArgList @('get', '--service', '__missing__', '--intent', 'readiness probe') -TimeoutSeconds 3
    if ($probe.Out.Contains('unknown service')) { $ready = $true; break }
    Start-Sleep -Milliseconds 100
  }
  if (-not $ready) { Fail 'daemon did not answer readiness probe' }

  $r = Invoke-Prout -ArgList @('serve') -TimeoutSeconds 5
  if ($r.Code -eq -999) { Fail 'second daemon hung instead of failing cleanly' }
  if ($r.Code -eq 0) { Fail 'second daemon unexpectedly bound live socket' }

  $child = "if (`$env:API_TOKEN -eq 'inject-secret') { exit 0 } else { exit 3 }"
  $r = Invoke-Prout -ArgList @('run', '--service', 'api', '--intent', 'update the local integration fixture with the configured token', '--', 'powershell', '-NoProfile', '-Command', $child)
  if ($r.Code -ne 0) { Fail "run injection failed: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  if (($r.Out + $r.Err).Contains('inject-secret')) { Fail 'run output leaked injected credential' }
  $lease = [regex]::Match($r.Err, 'lease-[0-9a-f]+').Value
  if (-not $lease) { Fail "could not parse lease id from run stderr: $($r.Err)" }
  if ($lease -eq 'lease-1') { Fail 'lease id remained sequential/predictable' }

  $r = Invoke-Prout -ArgList @('run', '--lease', $lease, '--', 'powershell', '-NoProfile', '-Command', $child)
  if ($r.Code -ne 0) { Fail "lease reuse failed without service: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  $r = Invoke-Prout -ArgList @('run', '--lease', $lease, '--', 'powershell', '-NoProfile', '-Command', 'exit 0')
  if ($r.Code -ne 11) { Fail "exhausted lease did not deny reuse: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }

  $r = Invoke-Prout -ArgList @('get', '--service', 'api', '--intent', 'read token for debugging')
  if ($r.Code -ne 11) { Fail "inject-only service was revealable: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  $r = Invoke-Prout -ArgList @('get', '--service', 'reveal', '--intent', 'read token for a one time shell export')
  if ($r.Code -ne 0) { Fail "reveal get failed: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  if (-not $r.Out.Contains('reveal-secret')) { Fail 'reveal get did not return credential' }

  $shouldNotRun = Join-Path $root 'should-not-run.txt'
  $r = Invoke-Prout -ArgList @('run', '--service', 'api', '--intent', 'fix', '--', 'powershell', '-NoProfile', '-Command', "Set-Content -Path '$shouldNotRun' -Value ran")
  if ($r.Code -ne 10) { Fail "vague intent did not return question exit 10: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  if (Test-Path $shouldNotRun) { Fail 'child command ran despite question response' }
  $question = $r.Out | ConvertFrom-Json
  $nid = $question.negotiation_id
  if (-not $nid) { Fail "could not parse negotiation id from question: $($r.Out)" }

  $r = Invoke-Prout -ArgList @('answer', $nid, 'check the token only inside this local integration child process', '--', 'powershell', '-NoProfile', '-Command', $child)
  if ($r.Code -ne 0) { Fail "answer did not resume and run child: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }

  $r = Invoke-Prout -ArgList @('audit', 'tail', '--n', '50')
  if ($r.Code -ne 0) { Fail "audit tail failed: $($r.Err)" }
  if (($r.Out + $r.Err).Contains('inject-secret') -or ($r.Out + $r.Err).Contains('reveal-secret')) { Fail 'audit tail leaked a credential' }

  $r = Invoke-Prout -ArgList @('audit', 'verify')
  if ($r.Code -ne 0) { Fail "audit verify failed before corruption: $($r.Err)" }

  $auditFile = Join-Path $root 'audit-ctest.jsonl'
  $text = Get-Content -Raw -Path $auditFile
  $text = $text -replace 'granted', 'changed'
  Set-Content -Path $auditFile -Value $text -NoNewline
  $r = Invoke-Prout -ArgList @('audit', 'verify')
  if ($r.Code -eq 0) { Fail 'audit verify did not detect manual corruption' }

  Write-Host 'prout CLI flow tests passed'
} finally {
  if ($daemon -and -not $daemon.HasExited) {
    try { $daemon.Kill() } catch {}
  }
}

