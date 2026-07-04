# Prout: Local Credential Leases for Agents

Prout is a local credential-lease daemon for AI agents and automation. An agent states an intent, the local arbiter recommends a short-lived lease, and Prout enforces the vault policy before a credential can be delivered.

Credentials are stored in an encrypted vault. The daemon decrypts them into locked memory after unlock and serves local CLI requests over an AF_UNIX socket using length-prefixed JSON frames. Credentials may be disclosed only through active leases, in one of two policy modes:

- `inject`: `prout run` negotiates approval, then `prout execute` receives the credential from the daemon and injects it into the child process environment. The CLI redacts the credential if the child prints it.
- `reveal`: `prout expose` negotiates approval, then final `prout expose --conversation <id>` prints the value for explicit capture.

The model recommends; code enforces. Unknown services, malformed arbiter output, unknown verdicts, zero ceilings, bad disclosure modes, and requests exceeding policy ceilings are denied or rejected before credential release.

## Current Commands

```powershell
prout vault init
prout vault add <service> --env <VAR> --disclosure inject|reveal --max-ttl <sec> --max-uses <n>
prout vault list

prout serve [--model <path>] [--backend cpu|gpu] [--vault <dir>]

prout run --service <service> --intent "<why>" [--agent <name>]
prout run --conversation <id> --details "<answer>" [--agent <name>]
prout execute --conversation <approved-id> -- <cmd...>
prout run --lease <lease-id> [--agent <name>] -- <cmd...>

prout expose --service <service> --intent "<why>" [--agent <name>]
prout expose --conversation <id> --details "<answer>" [--agent <name>]
prout expose --conversation <approved-id>

prout audit tail [--n <count>]
prout audit conversation <conversation-id>
prout audit verify
```

Exit codes are stable for agents: `0` success, `1` error, `10` question, `11` denied.

`serve --model <path>` is optional. Without a model, Prout uses a deterministic heuristic arbiter so local smoke tests and agent scripts can exercise the full vault/lease/audit flow. With a model, Prout uses the LiteRT-LM C Conversation API.

## Run and Execute Flow

Use one terminal for the daemon:

```powershell
.\dist\prout.exe serve --model C:\Users\eerwi\models\gemma-4-E2B-it-litert-lm\gemma-4-E2B-it.litertlm --backend cpu
```

Use another terminal to negotiate a credential lease. `run` does not execute the website/API check; it returns safe JSON metadata and, when approved, a `conversation_id` for the next command.

```powershell
.\dist\prout.exe run --service ml.huggingface --intent "checking the token is valid against the website" --agent local
```

If the response has `"status":"question"`, answer with the returned conversation id:

```powershell
.\dist\prout.exe run --conversation <question-conversation-id> --details "Validate the Hugging Face token with the whoami API once, without changing account state." --agent local
```

When the response has `"status":"granted"`, pass its `conversation_id` to `execute`. The daemon injects the credential into the environment variable configured by `vault add --env`; this example assumes the service was added with `--env HF_TOKEN`.

```powershell
.\dist\prout.exe execute --conversation <approved-conversation-id> -- powershell -NoProfile -Command '$h=@{Authorization=("Bearer " + $env:HF_TOKEN)}; Invoke-RestMethod -Headers $h -Uri https://huggingface.co/api/whoami-v2'
```

## Arbiter Schema

The external arbiter response format is one JSON object:

```json
{"type":"question","question":"What specifically will you do?"}
```

```json
{"type":"lease","ttl_seconds":300,"max_uses":1,"rationale":"Read-only diagnostic intent."}
```

```json
{"type":"deny","rationale":"Intent is too vague for this credential."}
```

Lease terms are clamped to the service policy ceilings in code.

## Environment

- `PROUT_HOME`: vault and audit directory. Defaults to `%LOCALAPPDATA%\prout` on Windows and `~/.prout` elsewhere.
- `PROUT_SOCKET`: daemon AF_UNIX socket path.
- `PROUT_PASSPHRASE`: non-interactive vault passphrase for tests and demos.
- `PROUT_MACHINE`: machine id used for `audit-<machine>.jsonl`.
- `PROUT_CREDENTIAL`: non-interactive credential input for `vault add`.

## Build

LiteRT-LM is vendored under `third_party/litert-lm/` and must not be modified. Build its C ABI shared library once with Bazel, then build Prout with CMake.

```powershell
cd third_party/litert-lm
bazelisk build //c:litert-lm --config=windows -c opt

cd ..\..
cmake --preset windows-release
cmake --build --preset windows-release
ctest --preset windows-release
```

The Windows build stages `dist/prout.exe`, `litert-lm.dll`, and the LiteRT-LM constraint provider DLL.

## Audit Log

Each machine appends only to its own `audit-<machine>.jsonl` file. Records are hash-chained and contain safe metadata: conversation ids, intent/details, service, verdict, rationale, lease terms, disclosure mode, command summaries, child exit codes, and redaction flags. Credential values and raw command output are never written to audit records. `prout audit conversation <id>` shows one conversation newest first, and `prout audit verify` recomputes the chain and detects manual record corruption.

## Security Invariants

1. Credentials never leave locked memory except across the local IPC/CLI boundary for an authorized lease delivery, and never into logs, audit records, errors, or normal `run` output.
2. The audit log is append-only. Prout never rewrites, reorders, or truncates existing records.
3. The model recommends; code enforces. No arbiter verdict authorizes decryption or delivery until validated against service policy.
4. `inject` and `reveal` are explicit policy modes. `expose` is denied for inject-only services.
5. `third_party/litert-lm/` is a vendored submodule and is not edited by Prout changes.

## Roadmap

Web vault management, sync, Ed25519-signed records, and curl proxy/request execution modes are roadmap items. They are not part of the current implemented surface.

