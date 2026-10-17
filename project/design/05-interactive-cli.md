# 05 · Interactive CLI (the pSIONIUM shell)

`psion` today is a plain scripting tool. This document defines the interactive, full-screen pSIONIUM shell the owner expects: beautiful, fast, keyboard-first, with the heritage of the original pSIONIUM terminal (black background, bold green text, `pSIONIUM>` prompt, command history), rebuilt to a professional standard.

## Two modes, one binary

| Mode | Started by | For |
|---|---|---|
| **Interactive shell** | `psion` with no arguments, or `psion shell` | People. Full-screen TUI with screens, panels, menus, live progress |
| **Scripting mode** | `psion <command> [flags]` | Scripts, CI, servers. Today's commands stay exactly compatible; new commands add `--json` output |

Every action in the shell has a scripting equivalent, and the shell shows that equivalent in its help bar ("Equivalent: `psion send report.pdf --to ravi@firm.com`") so people learn automation naturally.

## Look and feel

- **Launch animation** (≤ 600 ms, skippable with any key, off with `--no-animation` or in CI): the PORTAL VII pyramid drawn in block characters, a scanline wipe, then the `pSIONIUM` wordmark in a violet→pink gradient over a green "matrix" shimmer.
- **Themes:** `classic` (black, bold green, the original terminal), `portal` (default: near-black, violet/pink accents, green for success), `high-contrast`, `light`. `psion theme <name>` or Settings.
- **Layout:** header bar (account · org · plan · suite · connection), left navigation, main panel, bottom bar with key hints and the scripting equivalent, toast notifications for incoming transfers.
- **Typography in terminals:** box-drawing borders, rounded panels, Nerd Font icons if detected (fallback to ASCII), true color with 256-color and 16-color fallbacks.
- **Accessibility:** respects `NO_COLOR`, `--plain` (no full screen, line-by-line prompts), screen-reader friendly prompts, every action reachable by keyboard, no information conveyed by color alone.
- **Speed:** opens in under 150 ms; all network work async with spinners; never blocks typing.

## Screens

| Screen | Contents | Key actions |
|---|---|---|
| **Home** | Welcome, unread transfers, recent activity, quick actions, Scan summary, license status, tips | `s` send · `i` inbox · `e` encrypt · `d` decrypt · `q` scan · `/` command palette |
| **Send** | File picker (fuzzy search, multi-select, folders), recipients with verified badges, options (expiry, passcode, link), review, live upload progress with throughput and ETA | `Tab` next field · `Ctrl+Enter` send |
| **Inbox** | List of received transfers with sender badge, size, expiry; detail panel with files and activity | `Enter` open · `o` save decrypted · `x` save encrypted · `r` reply · `f` forward · `w` watch/auto-decrypt |
| **Sent** | Your transfers with per-recipient state; revoke, extend, resend | `R` revoke · `E` extend |
| **Encrypt / Decrypt (offline)** | Today's local features with a guided form: choose files, recipients (contacts or pasted keys), sign, chunk size; decrypt with signer requirement | |
| **Vaults** | Browse vaults, upload/download, members | |
| **Contacts** | People and teams, verification status, compare safety codes (QR rendered in the terminal) | `v` verify |
| **Keys & devices** | Identity fingerprint, key versions, devices list, approve a new device (scan its code), recovery kit status, rotate keys | |
| **Scan** | Choose paths and TLS hosts, live progress per file count, findings browser grouped by category with code excerpts, export (Markdown/JSON/CBOM/HTML), upload to dashboard | `Enter` open finding · `e` export |
| **Account / Org / License** | Signed-in user, org, role, plan, seats, entitlements, license expiry, upgrade link | |
| **Settings** | Theme, animation, default delivery mode, auto-decrypt folders, notifications, proxy, telemetry (off by default) | |
| **Help** | Interactive tutorial (encrypt and decrypt a sample file in 60 seconds), keyboard map, docs links, `psion doctor` | |

## Command palette and the classic prompt

- `/` or `Ctrl+K` opens a fuzzy command palette with every action.
- `:` opens the classic prompt line `pSIONIUM> ` at the bottom with history (↑/↓), tab completion of commands, paths, contacts and flags. Commands typed here are the same as scripting commands without the `psion` prefix (`send report.pdf --to ravi@firm.com`). As built, `:` opens the **Console** screen, whose bottom line is the prompt and whose body keeps each command's output, like the original pSIONIUM terminal (see `DECISIONS.md`, 2026-10-16).
- Heritage commands from the original shell are kept as utilities: `encode`/`decode` (base64, hex, base32) and `compress`/`decompress` (zstd), separate from encryption.

## Scripting-mode commands (complete list)

| Command | Purpose | Status |
|---|---|---|
| `keygen`, `pubkey`, `encrypt`, `decrypt`, `inspect`, `passphrase`, `scan` | Local operations | **Exist** |
| `login`, `logout`, `whoami` | Account sign-in via OAuth device flow (opens browser, shows code); tokens in OS keychain | Planned |
| `send <files> --to … [--link] [--expires 7d] [--passcode] [--message …]` | Create a transfer | Planned |
| `inbox [--watch] [--auto-decrypt DIR] [--json]` | List or watch incoming transfers | Planned |
| `open <transfer-id> [-o DIR] [--encrypted]` | Download and decrypt (or keep encrypted) | Planned |
| `sent`, `revoke <id>`, `extend <id> --expires …` | Manage sent transfers | Planned |
| `request --title … [--expires …]` | Create a request-files link | Planned |
| `contacts [add|verify|list]` | Contacts and verification | Planned |
| `devices [list|approve|remove]`, `recovery [status|new-kit]` | Devices and recovery | Planned |
| `vault [ls|get|put|members]` | Vaults | Planned |
| `org`, `license [status|activate FILE]` | Org info, license status, offline license activation (self-hosted) | Planned |
| `scan --upload` | Upload results to the Scan dashboard | Planned |
| `encode`, `decode`, `compress`, `decompress` | Heritage utilities | Planned |
| `shell`, `theme` | Open the shell; show or save its theme | **Exist** |
| `config`, `doctor`, `update`, `completions <shell>` | Settings, diagnostics, self-update (verified signature), shell completions | Planned |

All planned commands support `--json` and exit codes: 0 success, 1 error, 2 policy/findings failure, 3 authentication required, 4 license/entitlement required.

## Accounts and licensing in the CLI

- Without login: local features (keygen/encrypt/decrypt/sign/scan) work fully. This is the open-source core and stays free forever.
- With login: transfer, inbox, contacts, vaults, scan upload, org features, according to the org's entitlements. The CLI shows a friendly upgrade panel when an entitlement is missing (exit code 4 in scripting mode).
- The CLI caches the signed license from the service for offline display and verifies its signature (08). Enforcement is on the server; the CLI only explains.
- Server/automation use: `psion login --api-key` (scoped API key) for headless machines.

## Tech choices

- Rust, same crate (`crates/psion`). `clap` for scripting mode, `ratatui` + `crossterm` for the TUI, `tokio` + `reqwest` (rustls, X25519MLKEM768) for the API, `keyring` for OS keychain, `notify` for watch folders, `indicatif` for scripting-mode progress, `nucleo` for fuzzy search, `qrcode` for terminal QR codes.
- Shared API client crate `psionium-client` (generated types from the OpenAPI spec) used by the CLI and the Flutter apps' Rust layer.
- Snapshot tests for every screen (`insta`) in each theme and at 80×24 and 200×60; end-to-end tests drive the shell with a pseudo-terminal.

## Acceptance

- A new user can install, open `psion`, take the tutorial, sign in, send a file to a colleague and see it opened, without reading docs.
- Every screen is usable at 80×24, in `classic` and `high-contrast` themes, and with `NO_COLOR`.
- All existing scripting commands and tests keep passing unchanged.
