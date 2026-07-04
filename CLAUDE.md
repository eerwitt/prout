# CLAUDE.md

Prout is currently a local credential-lease daemon.

Read this before making changes. The implemented surface is a single `prout` executable with these areas:

```text
src/cli/       subcommand dispatcher and trusted client delivery
src/daemon/    local lease daemon, pending questions, in-memory lease table
src/ipc/       AF_UNIX length-prefixed JSON frames
src/vault/     encrypted vault, service policies, disclosure mode
src/audit/     append-only per-machine hash-chained JSONL audit log
src/arbiter/   heuristic test arbiter or LiteRT-LM Conversation C API backend
src/common/    paths, passphrase prompt, locked memory helpers
tests/scripts/ script-based CTest smoke coverage
third_party/   vendored dependencies; never edit third_party/litert-lm/
```

## Build

LiteRT-LM is built out of band by Bazel, then Prout is built by CMake:

```powershell
cd third_party/litert-lm
bazelisk build //c:litert-lm --config=windows -c opt

cd ..\..
cmake --preset windows-release
cmake --build --preset windows-release
ctest --preset windows-release
```

The CMake build fetches/builds Abseil, nlohmann/json, and static libcurl, links Monocypher from `third_party/monocypher`, and imports the LiteRT-LM C ABI DLL/import library from `third_party/litert-lm/bazel-bin/c`.

## Formatting

C++ source uses `.clang-format` with LLVM style and `#pragma once` headers.
Run formatting before submitting C++ changes:

```powershell
cmake --build --preset windows-release --target format
ctest --preset windows-release -R prout_clang_format
```

CMake locates `clang-format` from `PATH` or the Visual Studio Community LLVM tools directory. Configuration fails with a fatal error if it cannot be found. The format target and test cover project `src/*.cc` and `src/*.h` files only; do not format vendored code under `third_party/`.

## Current Behavior

- `prout vault init/add/list` manages an encrypted local vault.
- `prout serve` unlocks the vault, creates the arbiter, listens on `PROUT_SOCKET`, and owns all active leases.
- `prout run --service ... --intent ...` and `prout run --conversation ... --details ...` negotiate only and return safe JSON metadata with transient conversation ids.
- `prout execute --conversation <approved-id> -- <cmd...>` consumes an approved run conversation, injects the credential into only the child environment for `disclosure=inject` services, and redacts leaked credential bytes in child output.
- `prout run --lease <id> -- <cmd...>` remains as compatibility reuse for active daemon leases.
- `prout expose --service ... --intent ...` negotiates reveal-mode approval; final `prout expose --conversation <approved-id>` consumes the approved expose conversation and prints the credential.
- `prout audit tail/verify/conversation` reads this machine's audit log, verifies the hash chain, and shows safe conversation metadata newest first.

Exit codes: `0` success, `1` error, `10` question, `11` denied.

## Arbiter Contract

The stable external JSON shape is:

- `{"type":"question","question":"..."}`
- `{"type":"lease","ttl_seconds":300,"max_uses":1,"rationale":"..."}`
- `{"type":"deny","rationale":"..."}`

The parser accepts only the `type` schema. Code clamps TTL and uses to policy ceilings and denies zero ceilings.

## Security Invariants

1. Credentials never leave locked memory except inside an authorized request. Do not put credentials in stdout/stderr except final `prout expose --conversation <approved-id>` for reveal-mode services, logs, audit records, errors, docs, or tests.
2. The audit log is append-only. Never rewrite, reorder, or truncate existing records; each machine writes only to its own `audit-<machine>.jsonl`.
3. The model recommends; code enforces. Unknown services, malformed model JSON, unknown verdicts, bad disclosure modes, or zero ceilings must deny/error before credential release.
4. Do not modify `third_party/litert-lm/`; use only the LiteRT-LM C ABI in `c/engine.h`.
5. Memory locking must exist on Windows and POSIX for decrypted secrets and keys (`VirtualLock` / `mlock`).
6. Lease IDs are opaque random bearer capabilities (`lease-` plus 256-bit hex), not counters or stable identifiers.
7. Local IPC is protected by owner-only socket placement/permissions. POSIX validates peer identity with OS credentials where available (`SO_PEERCRED` on Linux, `getpeereid` on macOS/BSD). Windows AF_UNIX peer identity is not exposed through the checked SDK headers, so owner-only ACLs and the user-local socket directory are the protection boundary.

## LiteRT-LM Facts

- Build with Bazel 7.6.1 via bazelisk; the C ABI target is `//c:litert-lm`.
- Use the Conversation C API (`litert_lm_conversation_create`, `litert_lm_conversation_send_message`).
- Do not include LiteRT-LM C++ runtime headers.
- Native models use `.litertlm` files such as the LiteRT Gemma community builds; omitting `--model` intentionally uses the heuristic backend for tests.

## Roadmap Only

Web UI, sync, Ed25519 signing, HTTP execution/filtering, and curl proxy mode are roadmap items. Do not document them as current behavior unless they are implemented and tested.

