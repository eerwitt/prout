---
name: prout-credential-access
description: Trigger when an agent needs to run a command with a locally stored Prout credential, negotiate a Prout lease, answer Prout arbiter questions, or explicitly reveal a credential through Prout when run/inject cannot satisfy the task.
---

# Prout Credential Access

Use this skill when a task requires access to a credential stored in Prout. Prout is a local credential-lease daemon: the arbiter recommends, but Prout enforces the service policy before any credential can be delivered.

Prefer the safer `run` plus `execute` flow for ordinary credential-backed commands. Use `expose` only when the raw credential value itself must be revealed and the task intent justifies that higher-risk path.

## Prerequisites

First choose the Prout executable:

1. If working inside the Prout repository and `prout` exists, use `prout`.
2. Otherwise use `prout` from `PATH`.
3. If no Prout executable is available, stop and report that Prout is unavailable.

Do not modify `third_party/litert-lm/`.

## Safer Run Flow

Use this flow when a command can receive the credential through an injected child-process environment variable.

Start by negotiating a run lease:

```powershell
prout run --service <service> --intent "<specific purpose>" --agent <agent-name> -- <command...>
```

If using `prout` from `PATH`, replace `prout` with `prout`.

Inspect the JSON response:

- If `status` is `"granted"`, treat `lease_id` as a bearer capability and execute exactly once with:

```powershell
prout execute --lease <lease_id>
```

- If `status` is `"question"`, answer the returned `conversation_id` with specific details:

```powershell
prout run --conversation <conversation_id> --details "<specific answer>" --agent <agent-name>
```

Then inspect the follow-up JSON response. Execute only after a `"granted"` response.

- If `status` is `"denied"` or `"error"`, stop. Report the safe rationale or error without retrying with vague or broadened intent.

Run negotiation stores the command with the conversation. Do not change the command when answering questions; provide details that explain the already-requested action.

## Reveal Flow

Use `expose` only when the task truly requires the raw credential value and an injected command cannot satisfy the request. Do not use `expose` for inject-only services; Prout will deny it, and you should return to the safer run flow.

Negotiate reveal-mode approval:

```powershell
prout expose --service <service> --intent "<why the raw credential itself is required>" --agent <agent-name>
```

If the response has `status` `"question"`, answer with:

```powershell
prout expose --conversation <conversation_id> --details "<specific answer>" --agent <agent-name>
```

Only after a `"granted"` response, reveal the credential with:

```powershell
prout expose --lease <lease_id>
```

After reveal, do not echo, log, summarize, persist, or include the exposed value in chat. Use it only for the authorized request.

## Writing Commands and Intents

Keep intents specific, bounded, and tied to the target service. Prefer read-only validation when possible, such as checking identity, listing minimal metadata, or performing a single non-mutating API request.

Write commands so the credential is consumed by the child process after Prout injects it. In PowerShell, escape child environment references with a backtick so the parent shell does not expand them before Prout runs the command:

```powershell
prout run --service ml.huggingface --intent "validate the Hugging Face token with one read-only whoami request" --agent local -- powershell -NoProfile -Command "curl.exe -4 -H ('Authorization: Bearer ' + `$env:HF_TOKEN) 'https://huggingface.co/api/whoami-v2'"
```

Keep the child command on one line. Avoid commands that print environment variables, dump process state, enable verbose credential logging, or write the credential to disk.

Escaping depends on which tool issues the `prout run` command, because the outer shell parses the child PowerShell string before Prout ever sees it:

- Bash tool (POSIX shell): a bare `$env:HF_TOKEN` or `$me` inside the double-quoted command is expanded by bash itself, not passed through literally. Escape every `$` intended for the child PowerShell process as `\$env:HF_TOKEN`, `\$me`, etc.
- PowerShell tool: the command line is itself PowerShell, so a bare `$env:HF_TOKEN` is expanded by the outer PowerShell before Prout runs. Escape it with a backtick, e.g. `` `$env:HF_TOKEN ``, `` `$me ``, so the literal `$...` reaches the child process.

Verify the stored command is correct before consuming the lease: `prout execute` runs exactly what was captured during `run` negotiation, so a bad escape only surfaces as a parse error at execute time and the lease is spent. If execute fails on a quoting error, negotiate a fresh lease with corrected escaping rather than retrying the same lease.

## Security Rules

- Never place credentials in logs, chat responses, audit text, filenames, command summaries, error messages, or test artifacts.
- Never rewrite, reorder, or truncate Prout audit logs. The audit log is append-only and each machine writes only to its own log file.
- Treat lease IDs as bearer capabilities. Do not share them unnecessarily, persist them, or include them in broad logs.
- The model recommends; code enforces. Do not assume an arbiter grant is sufficient until Prout returns a schema-valid `"granted"` response that satisfies service policy.
- Credentials must not leave locked memory except inside an authorized `execute` delivery or final `expose --lease` reveal.
- Do not modify `third_party/litert-lm/`.
