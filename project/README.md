# pSIONIUM project folder — start here

This folder is the single source of truth for **why pSIONIUM exists, where it stands, and what to do next**. If you are an agent (or a person) picking up this project, everything you need to start is here.

| File | What it holds |
|---|---|
| [`VISION.md`](VISION.md) | What pSIONIUM is meant to become, for whom, and the principles that never change |
| [`design/`](design/README.md) | **The complete platform design**: products and journeys, architecture, security model, secure transfer, interactive CLI, website and apps, accounts and admin, licensing, business operations, Scan, API/SDKs, quality and operations, research ideas, owner decisions |
| [`STATUS.md`](STATUS.md) | What exists today, how it was verified, and what is waiting on the owner |
| [`ROADMAP.md`](ROADMAP.md) | The ordered list of work, with "done when" for each stage |
| [`RULES.md`](RULES.md) | The owner's standing rules and this repository's engineering rules, plus the verification suite |
| [`DECISIONS.md`](DECISIONS.md) | Key decisions and why they were made, so they are not re-argued |
| [`LOG.md`](LOG.md) | One entry per working session, newest first |

## Instructions for a new agent

1. **Read** `RULES.md` first, then `VISION.md`, `STATUS.md`, `ROADMAP.md`, `design/README.md`, and the last few entries of `LOG.md`. Skim `DECISIONS.md` before proposing any change of direction.
2. **Check reality before trusting the docs.** Run `git log --oneline -5` and `git status`, check the latest CI run (`gh run list --repo Chandu00756/psionium --limit 3`), and run the verification suite in `RULES.md`. If anything disagrees with `STATUS.md`, report it to the owner and correct `STATUS.md`.
3. **Pick the work.** Take the first unchecked item in `ROADMAP.md` that does not need an owner decision. **Read the design document the item points to before writing any code, and build exactly that design.** If the item depends on an open decision in `design/14-owner-decisions.md`, ask the owner that one question (with the recommendation) and wait. Do nothing outward-facing until they answer.
4. **Do the work under the rules.** Impact check before each change, re-verify after, no git and no subagents without permission.
5. **Update this folder before you finish**, every session, even if the work is unfinished:
   - `STATUS.md`: change what is now true (with the commit or evidence), and the "Last updated" line.
   - `ROADMAP.md`: tick finished items, add newly discovered work in the right stage.
   - `DECISIONS.md`: add any decision you made or the owner made, with the reason.
   - `design/…`: if the owner approved a design change, edit the design document in the same change (never let code and design disagree).
   - `design/14-owner-decisions.md`: mark decisions answered.
   - `LOG.md`: add a dated entry at the top: what you did, how you verified it, what is left, and anything the next agent must know.
6. **Report to the owner** in a few short points: where things stand, what you changed, what you need from them.

## Where things are

| What | Where |
|---|---|
| This repository | `~/psionium`, GitHub `Chandu00756/psionium` (public since 2026-10-16), branch `main` |
| Rust crates | `crates/psionium-core` (crypto and format), `crates/psion` (CLI), `crates/psionium-scan` (scanner) |
| Format spec, threat model, scanner guide, readiness checklist | `docs/` |
| Second implementation (Go, from the spec) | `interop/go` |
| CI and release | `.github/workflows/ci.yml`, `.github/workflows/release.yml`; installer `install.sh` |
| Recovered original code | `legacy` branch; `~/Desktop/pSIONIUM_recovered` |
| Owner's original idea documents | `~/Desktop/PVII` |
| Website (portalvii.com) | `~/P7Ultra/portalvii-website2/packages/frontend`, pSIONIUM pages under `src/app/pages/psionium` and `src/app/pages/resources/psionium` |
| Original plan with market research | "pSIONIUM 3 Plan" artifact, https://claude.ai/artifact/YG728QHRuaWFDMSsbxRyuq |
