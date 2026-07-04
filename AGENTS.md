# AGENTS.md

Agent guidance for this repository lives in **[CLAUDE.md](CLAUDE.md)**. Read it before making any change — it covers the repo layout, the two-step build (Bazel for the vendored LiteRT-LM C ABI, CMake for Prout), coding conventions, and verified LiteRT-LM facts you should not re-derive.

## Non-negotiable security invariants

Even if you read nothing else:

1. **Credentials never leave locked memory except inside an authorized request** — never into stdout/stderr, logs, audit records, error messages, or agent-visible responses.
2. **The audit log is append-only.** Never rewrite, reorder, or truncate existing records; each machine writes only to its own log file.
3. **The model recommends; code enforces.** No arbiter verdict authorizes credential decryption until schema-validated against the service policy.
4. **Never modify `third_party/litert-lm/`** — it is a vendored submodule.
