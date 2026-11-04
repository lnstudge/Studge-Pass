<!-- Phase 6: command-line client. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 6: the `studge` command-line client** (clap).

Commands:
- `init`: create an account on a relay URL or in a folder. Print the Secret Key once and write a recovery-kit text file.
- `login`, `unlock`, `lock`, `status`, `sync`
- `list [--vault]`
- `get <query> [--field password|username|totp]`: copies to the clipboard with arboard and clears it after 30 s. Printing to stdout needs an explicit `--print` flag.
- `add login`, `edit`, `rm`, `generate`, `totp <query>`
- `import <format> <file>`
- `export <format> <file>`: plaintext formats need `--i-understand-this-is-plaintext`.
- `health` (summary), `devices list|revoke`, `config`

Rules:
- Never accept the master password as an argument. Read it with rpassword. STUDGE_PASSWORD is allowed only with a printed warning.
- Keep the unlocked session in the OS credential store (keyring crate) for a configurable number of minutes. Never write plaintext to disk.

Write integration tests (assert_cmd) against an in-process relay and against a folder transport. Add a Quickstart to README.md. Run every check, update PROGRESS.md and commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.
