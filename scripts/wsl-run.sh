#!/usr/bin/env bash
# Studge Pass: run a build/test command inside WSL Ubuntu.
# Called by ../x.ps1, which passes the command in $STUDGE_CMD.
#
# Why: Windows Smart App Control blocks the unsigned helper programs that Rust
# compiles on Windows, so cargo, pnpm and node run in Linux instead.
# Sources stay on C:\dev\Studge-Pass (/mnt/c/...); build output goes to the
# faster Linux disk.
set -eo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/studge-pass/target}"
# Tells project tooling it runs under WSL on a Windows drive. Vite/Storybook
# must use polling file watching, because edits made from Windows do not
# raise Linux file-change events on /mnt/c.
export STUDGE_WSL=1
export CHOKIDAR_USEPOLLING=1

cd "$(dirname "$0")/.."

if [ -z "${STUDGE_CMD:-}" ]; then
  echo "usage: .\\x.ps1 <command> [args...]" >&2
  exit 2
fi

eval "$STUDGE_CMD"
