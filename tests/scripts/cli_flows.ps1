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

function Sync-VaultLogs([string]$From, [string]$To) {
  Get-ChildItem -Path $From -Filter 'vault-*.jsonl' | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination (Join-Path $To $_.Name) -Force
  }
}

try {
  $r = Invoke-Prout -ArgList @('vault', 'init')
  if ($r.Code -ne 0) { Fail "vault init failed: $($r.Err)" }

  $env:PROUT_CREDENTIAL = 'inject-secret'
  $r = Invoke-Prout -ArgList @('vault', 'add', 'github/personal', '--inject-env', 'API_TOKEN', '--website', 'https://api.example.test/account', '--company', 'Example API', '--details', 'local integration fixture token', '--disclosure', 'inject', '--max-ttl', '120', '--max-uses', '2', '--description', 'test api token', '--guidance', 'grant concrete local test intents')
  if ($r.Code -ne 0) { Fail "vault add inject failed: $($r.Err)" }

  $env:PROUT_CREDENTIAL = 'reveal-secret'
  $r = Invoke-Prout -ArgList @('vault', 'add', 'stripe:billing', '--inject-env', 'REVEAL_TOKEN', '--website', 'https://billing.example.test', '--company', 'Billing Example', '--details', 'reveal mode fixture token', '--disclosure', 'reveal', '--max-ttl', '120', '--max-uses', '1', '--description', 'test reveal token')
  if ($r.Code -ne 0) { Fail "vault add reveal failed: $($r.Err)" }
  $env:PROUT_CREDENTIAL = ''

  $r = Invoke-Prout -ArgList @('vault', 'list')
  if ($r.Code -ne 0) { Fail "vault list failed: $($r.Err)" }
  if (($r.Out + $r.Err).Contains('inject-secret') -or ($r.Out + $r.Err).Contains('reveal-secret')) { Fail 'vault list leaked a credential' }

  $r = Invoke-Prout -ArgList @('vault', 'edit', 'github/personal', '--company', 'Example API Edited', '--details', 'edited local integration fixture token')
  if ($r.Code -ne 0) { Fail "vault edit failed: $($r.Err)" }

  $env:PROUT_CREDENTIAL = 'rotate-secret-one'
  $r = Invoke-Prout -ArgList @('vault', 'add', 'rotate-fixture', '--inject-env', 'ROTATE_TOKEN', '--website', 'https://rotate.example.test', '--company', 'Rotate Example', '--details', 'rotation fixture', '--description', 'rotation fixture')
  if ($r.Code -ne 0) { Fail "vault add rotate fixture failed: $($r.Err)" }
  $env:PROUT_CREDENTIAL = 'rotated-inject-secret'
  $r = Invoke-Prout -ArgList @('vault', 'rotate', 'rotate-fixture')
  if ($r.Code -ne 0) { Fail "vault rotate failed: $($r.Err)" }
  $env:PROUT_CREDENTIAL = ''
  $r = Invoke-Prout -ArgList @('vault', 'history', 'rotate-fixture')
  if ($r.Code -ne 0) { Fail "vault history failed: $($r.Err)" }
  if (($r.Out + $r.Err).Contains('rotated-inject-secret')) { Fail 'vault history leaked a rotated credential' }
  if (-not $r.Out.Contains('rotate')) { Fail "vault history did not show rotation: $($r.Out)" }
  $r = Invoke-Prout -ArgList @('vault', 'verify')
  if ($r.Code -ne 0) { Fail "vault verify failed: $($r.Err)" }

  $env:PROUT_CREDENTIAL = 'delete-secret'
  $r = Invoke-Prout -ArgList @('vault', 'add', 'aws:prod/admin', '--inject-env', 'DELETE_TOKEN', '--website', 'https://delete.example.test', '--company', 'Delete Example', '--details', 'temporary delete fixture', '--description', 'delete fixture')
  if ($r.Code -ne 0) { Fail "vault add delete fixture failed: $($r.Err)" }
  $env:PROUT_CREDENTIAL = ''
  $r = Invoke-Prout -ArgList @('vault', 'delete', 'aws:prod/admin')
  if ($r.Code -ne 0) { Fail "vault delete failed: $($r.Err)" }

  $daemonPsi = [System.Diagnostics.ProcessStartInfo]::new()
  $daemonPsi.FileName = $ProutExe
  $daemonPsi.Arguments = 'serve'
  $daemonPsi.UseShellExecute = $false
  $daemonPsi.RedirectStandardOutput = $true
  $daemonPsi.RedirectStandardError = $true
  $daemon = [System.Diagnostics.Process]::Start($daemonPsi)

  $ready = $false
  for ($i = 0; $i -lt 50; $i++) {
    $probe = Invoke-Prout -ArgList @('expose', '--service', '__missing__', '--intent', 'readiness probe') -TimeoutSeconds 3
    if (($probe.Out + $probe.Err).Contains('unknown service')) { $ready = $true; break }
    Start-Sleep -Milliseconds 100
  }
  if (-not $ready) { Fail 'daemon did not answer readiness probe' }

  $r = Invoke-Prout -ArgList @('serve') -TimeoutSeconds 5
  if ($r.Code -eq -999) { Fail 'second daemon hung instead of failing cleanly' }
  if ($r.Code -eq 0) { Fail 'second daemon unexpectedly bound live socket' }

  $child = "if (`$env:API_TOKEN -ne 'inject-secret') { exit 3 }; Write-Output `$env:API_TOKEN; exit 0"
  $r = Invoke-Prout -ArgList @('run', '--service', 'github/personal', '--intent', 'update the local integration fixture with the configured token', '--', 'powershell', '-NoProfile', '-Command', $child)
  if ($r.Code -ne 0) { Fail "run negotiation failed: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  if (($r.Out + $r.Err).Contains('inject-secret')) { Fail 'run negotiation leaked injected credential' }
  $grant = $r.Out | ConvertFrom-Json
  $cid = $grant.conversation_id
  if (-not $cid) { Fail "could not parse approved conversation id from run: $($r.Out)" }
  if ($cid -eq 'conv-1') { Fail 'conversation id remained sequential/predictable' }
  $lease = $grant.lease_id
  if (-not $lease) { Fail "could not parse lease id from run: $($r.Out)" }
  if ($grant.env_var -ne 'API_TOKEN') { Fail "run grant did not report injected env var: $($r.Out)" }

  $r = Invoke-Prout -ArgList @('execute', '--lease', $lease)
  if ($r.Code -ne 0) { Fail "execute injection failed: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  if (($r.Out + $r.Err).Contains('inject-secret')) { Fail 'execute output leaked injected credential' }
  if (-not $r.Out.Contains('*************')) { Fail "execute did not redact leaked credential bytes: out=$($r.Out)" }

  $r = Invoke-Prout -ArgList @('run', '--service', 'github/personal', '--intent', 'update the local integration fixture with the configured token', '--', 'powershell', '-NoProfile', '-Command', 'Invoke-WebRequest https://evil.example.test')
  if ($r.Code -ne 11) { Fail "domain mismatch was not denied during negotiation: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }

  $r = Invoke-Prout -ArgList @('execute', '--lease', $lease)
  if ($r.Code -ne 0) { Fail "second execute with lease failed: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }

  $r = Invoke-Prout -ArgList @('execute', '--lease', $lease)
  if ($r.Code -ne 11 -and $r.Code -ne 1) { Fail "exhausted lease was not rejected: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }

  $r = Invoke-Prout -ArgList @('run', '--lease', $lease, '--', 'powershell', '-NoProfile', '-Command', "if (`$env:API_TOKEN -eq 'inject-secret') { exit 0 } else { exit 3 }")
  if ($r.Code -eq 0) { Fail "run --lease unexpectedly executed: out=$($r.Out) err=$($r.Err)" }

  $r = Invoke-Prout -ArgList @('expose', '--service', 'github/personal', '--intent', 'read token for debugging')
  if ($r.Code -ne 11) { Fail "inject-only service was revealable: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  $r = Invoke-Prout -ArgList @('expose', '--service', 'stripe:billing', '--intent', 'read token for a one time shell export')
  if ($r.Code -ne 0) { Fail "reveal expose negotiation failed: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  if (($r.Out + $r.Err).Contains('reveal-secret')) { Fail 'reveal expose negotiation leaked credential' }
  $revealGrant = $r.Out | ConvertFrom-Json
  $revealCid = $revealGrant.conversation_id
  if (-not $revealCid) { Fail "could not parse reveal conversation id: $($r.Out)" }
  $revealLease = $revealGrant.lease_id
  if (-not $revealLease) { Fail "could not parse reveal lease id: $($r.Out)" }
  $r = Invoke-Prout -ArgList @('expose', '--conversation', $revealCid)
  if ($r.Code -eq 0) { Fail "final expose by conversation unexpectedly succeeded: out=$($r.Out) err=$($r.Err)" }
  $r = Invoke-Prout -ArgList @('expose', '--lease', $revealLease)
  if ($r.Code -ne 0) { Fail "final expose failed: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  if (-not $r.Out.Contains('reveal-secret')) { Fail 'final expose did not return credential' }

  $shouldNotRun = Join-Path $root 'should-not-run.txt'
  $r = Invoke-Prout -ArgList @('run', '--service', 'github/personal', '--intent', 'fix', '--', 'powershell', '-NoProfile', '-Command', "if (`$env:API_TOKEN -eq 'inject-secret') { exit 0 } else { exit 3 }")
  if ($r.Code -ne 10) { Fail "vague intent did not return question exit 10: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  if (Test-Path $shouldNotRun) { Fail 'child command ran despite question response' }
  $question = $r.Out | ConvertFrom-Json
  $qid = $question.conversation_id
  if (-not $qid) { Fail "could not parse conversation id from question: $($r.Out)" }

  $r = Invoke-Prout -ArgList @('run', '--conversation', $qid, '--details', 'check the token only inside this local integration child process')
  if ($r.Code -ne 0) { Fail "run details did not resume negotiation: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }
  $grant = $r.Out | ConvertFrom-Json
  $cid2 = $grant.conversation_id
  $r = Invoke-Prout -ArgList @('execute', '--lease', $grant.lease_id)
  if ($r.Code -ne 0) { Fail "execute after details failed: rc=$($r.Code) out=$($r.Out) err=$($r.Err)" }

  $r = Invoke-Prout -ArgList @('audit', 'conversation', $cid)
  if ($r.Code -ne 0) { Fail "audit conversation failed: $($r.Err)" }
  if (-not $r.Out.Contains('execute_result')) { Fail "audit conversation did not show execute metadata: $($r.Out)" }

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

  $syncA = Join-Path $root 'sync-a'
  $syncB = Join-Path $root 'sync-b'
  New-Item -ItemType Directory -Force -Path $syncA, $syncB | Out-Null
  $oldHome = $env:PROUT_HOME
  $oldMachine = $env:PROUT_MACHINE
  try {
    $env:PROUT_HOME = $syncA
    $env:PROUT_MACHINE = 'sync-a'
    $r = Invoke-Prout -ArgList @('vault', 'init')
    if ($r.Code -ne 0) { Fail "sync vault init failed: $($r.Err)" }
    $env:PROUT_CREDENTIAL = 'sync-secret-a'
    $r = Invoke-Prout -ArgList @('vault', 'add', 'shared', '--inject-env', 'SYNC_TOKEN', '--website', 'https://sync.example.test', '--company', 'SyncCo', '--details', 'base details', '--description', 'sync fixture')
    if ($r.Code -ne 0) { Fail "sync add shared failed: $($r.Err)" }
    $env:PROUT_CREDENTIAL = 'only-a-secret'
    $r = Invoke-Prout -ArgList @('vault', 'add', 'only-a', '--inject-env', 'ONLY_A_TOKEN', '--website', 'https://a.example.test', '--company', 'A', '--details', 'a details', '--description', 'a fixture')
    if ($r.Code -ne 0) { Fail "sync add only-a failed: $($r.Err)" }
    Sync-VaultLogs $syncA $syncB

    $env:PROUT_HOME = $syncB
    $env:PROUT_MACHINE = 'sync-b'
    $env:PROUT_CREDENTIAL = 'only-b-secret'
    $r = Invoke-Prout -ArgList @('vault', 'add', 'only-b', '--inject-env', 'ONLY_B_TOKEN', '--website', 'https://b.example.test', '--company', 'B', '--details', 'b details', '--description', 'b fixture')
    if ($r.Code -ne 0) { Fail "sync add only-b failed: $($r.Err)" }
    $r = Invoke-Prout -ArgList @('vault', 'edit', 'shared', '--details', 'details from b')
    if ($r.Code -ne 0) { Fail "sync edit details failed: $($r.Err)" }
    $env:PROUT_CREDENTIAL = 'sync-secret-b'
    $r = Invoke-Prout -ArgList @('vault', 'rotate', 'shared')
    if ($r.Code -ne 0) { Fail "sync rotate shared failed: $($r.Err)" }

    $env:PROUT_HOME = $syncA
    $env:PROUT_MACHINE = 'sync-a'
    $r = Invoke-Prout -ArgList @('vault', 'edit', 'shared', '--company', 'SyncCo A')
    if ($r.Code -ne 0) { Fail "sync edit company failed: $($r.Err)" }

    Sync-VaultLogs $syncA $syncB
    Sync-VaultLogs $syncB $syncA
    $r = Invoke-Prout -ArgList @('vault', 'list')
    if ($r.Code -ne 0) { Fail "sync merged list failed: $($r.Err)" }
    if (-not $r.Out.Contains('only-a') -or -not $r.Out.Contains('only-b')) { Fail "sync union lost a service: $($r.Out)" }
    if (-not $r.Out.Contains('SyncCo A')) { Fail "sync merge lost company edit: $($r.Out)" }
    $r = Invoke-Prout -ArgList @('vault', 'history', 'shared')
    if ($r.Code -ne 0) { Fail "sync history failed: $($r.Err)" }
    if (($r.Out + $r.Err).Contains('sync-secret-a') -or ($r.Out + $r.Err).Contains('sync-secret-b')) { Fail 'sync history leaked credential bytes' }
    if (-not $r.Out.Contains('rotate')) { Fail "sync history omitted credential rotation: $($r.Out)" }
    $r = Invoke-Prout -ArgList @('vault', 'verify')
    if ($r.Code -ne 0) { Fail "sync vault verify failed: $($r.Err)" }

    $vaultFile = Join-Path $syncA 'vault-sync-a.jsonl'
    $vaultText = Get-Content -Raw -Path $vaultFile
    $vaultText = $vaultText -replace 'mutation', 'mutated'
    Set-Content -Path $vaultFile -Value $vaultText -NoNewline
    $r = Invoke-Prout -ArgList @('vault', 'verify')
    if ($r.Code -eq 0) { Fail 'vault verify did not detect manual corruption' }
  } finally {
    $env:PROUT_HOME = $oldHome
    $env:PROUT_MACHINE = $oldMachine
    $env:PROUT_CREDENTIAL = ''
  }

  Write-Host 'prout CLI flow tests passed'
} finally {
  if ($daemon -and -not $daemon.HasExited) {
    try {
      $daemon.Kill()
      $daemon.WaitForExit(5000) | Out-Null
    } catch {}
  }
}

