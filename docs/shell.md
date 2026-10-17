# The pSIONIUM shell

Run `psion` with no command (or `psion shell`) in a terminal to open the interactive shell. Everything it does runs on your computer: identities, encryption, signatures and scans. `psion <command>` is unchanged for scripts, and every action in the shell shows its scripting equivalent in the bottom bar.

```bash
psion                      # open the shell
psion --theme classic      # with a theme, for this run only
psion --no-animation       # skip the launch animation
psion --plain              # a line-by-line pSIONIUM> prompt instead of the full screen
psion theme light          # save the default theme
```

New here? Press `t` in the shell for a one-minute tutorial: it creates a practice identity, encrypts and signs a file, inspects it and decrypts it, running the real `psion` commands in a temporary folder that is deleted afterwards.

## Screens

| Screen | What it does |
|---|---|
| Home | Your default identity, the last scan, quick actions |
| Encrypt | Encrypt a file to one or more `psionpk:` keys (or to yourself), signed with your identity |
| Decrypt | Decrypt a `.psen` file, optionally requiring a specific signer; Inspect shows a file's suite, recipients and signer without decrypting |
| Keys | Identities in `~/.psion`: suite, passphrase, fingerprint, public and verify keys; create one (`n`), choose the default (`m`) |
| Scan | Scan folders and TLS servers with live progress, browse findings by algorithm with what to do about each, and save the report as HTML, Markdown, JSON, SARIF or CBOM (`x`) |
| Console | The classic `pSIONIUM>` prompt: type any `psion` command without `psion`, with history and Tab completion of commands, flags and paths |
| Settings | Theme, launch animation, default identity |
| Help | Keys, what works today, and the tutorial |

Sending files to people, the inbox and contacts need pSIONIUM accounts, which are designed (`project/design/04-secure-transfer.md`) but not built yet.

## Keys

| Key | Where | Does |
|---|---|---|
| `Ctrl+K` or `/` | anywhere (`/` when not typing) | Command palette: type to find any action |
| `:` | when not typing | The `pSIONIUM>` prompt |
| `1`–`8` | when not typing | Jump to a screen |
| `↑` `↓` `Enter` | screen list | Choose and open a screen |
| `Tab` `Shift+Tab` | forms | Next and previous field |
| `→` | path fields | Accept the suggested completion |
| `Space` `←` `→` | toggles and choices | Change the value |
| `Esc` | anywhere | Back to the screen list (or close a window) |
| `F1` `?` | anywhere (`?` when not typing) | Help |
| `Ctrl+Q` `Ctrl+C` | anywhere | Quit |
| `e` `d` `q` `k` `t` | Home | Encrypt, decrypt, scan, keys, tutorial |

## Passphrases

The shell never stores a passphrase. When an action needs one, it is passed to `psion` through a pipe (`--passphrase-file -`), never through a file, an argument or the environment, and the field is cleared once the command starts. Commands typed at the `pSIONIUM>` prompt cannot ask for a passphrase (the full-screen shell owns the terminal), so use the Encrypt and Decrypt screens for protected identities, or `psion --plain`, where commands run as they do in a terminal.

## Themes and accessibility

`portal` (default; violet and pink), `classic` (the original pSIONIUM terminal: bold green on black), `high-contrast` and `light`. Colours adapt to the terminal (true colour, 256 or 16 colours). With `NO_COLOR` set, the shell draws without colours, using bold, underline and reverse video instead; no information is shown by colour alone. The shell needs a window of at least 60×16 and is designed for 80×24 and up.

On Windows, use Windows Terminal or PowerShell. Git Bash's own window (mintty) often does not give Windows programs a console, so the full-screen shell cannot start there; run `winpty psion` (winpty comes with Git for Windows), open Git Bash inside Windows Terminal, or use `psion --plain`.

## Files

Settings are saved in `config.toml` and the prompt history in `history` (readable only by you), in `$PSION_CONFIG_DIR` if set, otherwise `%APPDATA%\psion` on Windows, `$XDG_CONFIG_HOME/psion`, or `~/.config/psion`. Identities created in the shell go to `~/.psion` (created readable only by you).

## For scripts

- `psion` with no command and no terminal prints a usage error, as before.
- `--passphrase-file -` reads a passphrase from the first line of standard input (one line per passphrase, so `passphrase` can read the current and the new one in turn). It cannot be combined with reading the data from standard input.
- `PSION_NO_PROMPT=1` makes `psion` fail instead of asking for a passphrase.
- `psion --plain < commands.txt` runs a list of commands, one per line (`#` starts a comment).
