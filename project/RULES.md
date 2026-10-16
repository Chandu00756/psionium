# Rules for anyone working on pSIONIUM

These come from the owner's standing instructions and from what a security product needs. They override convenience.

## Owner's standing rules

1. **Never touch git without permission.** Do not commit, stage, amend, push, tag, or run destructive git commands unless the owner explicitly says yes for that specific action in the current conversation. Even then: new commits only, never amend or force-push. Leave the working tree in a clean, fixed state and report what changed.
2. **Impact check before every change.** Before adding, removing or modifying anything, find what depends on it (callers, tests, CI, docs, the website, the Go interop implementation, test vectors). After the change, run the relevant tests and builds, and say which dependents you checked and the result. If a dependent breaks, stop and report it; do not fix it without the owner's go-ahead, and do not call the original task done.
3. **Never conclude without re-verifying.** After any fix, run the full suite (below) and confirm the original symptom is gone. Only report success when both are true. Run long suites in the background while you check the symptom.
4. **No subagents or workflows** (Agent or Workflow tools) without the owner's explicit approval in the conversation. Do the work yourself with Read, Grep and Bash.
5. **Outward-facing actions need explicit confirmation:** making a repository public, publishing releases or tags, deploying the website, DNS, sending email, posting anywhere.
6. **Credentials:** never print secrets in chat; never enter the owner's real credentials anywhere; use test values only on local development hosts. The production TaskFlow server is read-only diagnostics, and its `.env` is never edited by an agent.

## Engineering rules for this repository

- **No new cryptography.** Only standardized algorithms from AWS-LC (Argon2id from RustCrypto). Any change to the format or key derivation needs a spec change in `docs/psen-v2.md`, a format version decision, and updated Go interop.
- **Test vectors are a contract.** Every 1.x release must decrypt `crates/psionium-core/tests/vectors`. Never regenerate them for 1.x; a format change means a new format version.
- **No `unsafe`** in pSIONIUM crates (`#![forbid(unsafe_code)]`).
- **Errors a user can cause get a clear message**, never a panic.
- **Claim only what is true** in docs, release notes and the website. No "certified", "compliant", uptime or usage numbers without evidence.
- **MSRV 1.88**, edition 2024. Keep `Cargo.lock` committed and builds `--locked`.

## The full verification suite

Run from the repository root; all must pass before reporting work as done.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
cargo build --locked -p psion && (cd interop/go && test -z "$(gofmt -l .)" && go vet ./... && PSION=../../target/debug/psion go test -count=1 ./...)
sh -n install.sh
```

For a release-sized change, also run a long mutation campaign: `PSIONIUM_MUTATIONS=200000 cargo test --release -p psionium-core --test mutation`, and a Linux check, for example `docker run --rm -v "$PWD":/src:ro -e CARGO_TARGET_DIR=/tmp/target rust:1-alpine sh -c 'apk add --no-cache musl-dev cmake make perl clang >/dev/null && cp -r /src /tmp/src && cd /tmp/src && cargo test --workspace --locked'`.
