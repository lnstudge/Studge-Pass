<#
.SYNOPSIS
  Runs a Studge Pass build, test or dev-server command inside WSL Ubuntu.

.DESCRIPTION
  Windows Smart App Control blocks the unsigned helper programs that Rust
  compiles on Windows, so every cargo, rustc, pnpm, node, npx and playwright
  command runs in Linux through this wrapper. Git and gh stay on Windows.

  The repository stays at its Windows path; inside WSL it is /mnt/<drive>/...
  Rust build output lives on the Linux disk (~/.cache/studge-pass/target).

.EXAMPLE
  .\x.ps1 cargo build --all
.EXAMPLE
  .\x.ps1 cargo test -p studge-core
.EXAMPLE
  .\x.ps1 "pnpm install && pnpm preview"
#>
$ErrorActionPreference = 'Stop'

if ($args.Count -eq 0) {
    Write-Host 'Usage: .\x.ps1 <command> [args...]   e.g. .\x.ps1 cargo test --all'
    exit 2
}

# C:\dev\Studge-Pass -> /mnt/c/dev/Studge-Pass
$repoWin = $PSScriptRoot
$drive = $repoWin.Substring(0, 1).ToLower()
$repoWsl = '/mnt/' + $drive + ($repoWin.Substring(2) -replace '\\', '/')

# Pass the command through an environment variable so PowerShell never
# mangles its quotes. WSLENV shares the variable with WSL.
$env:STUDGE_CMD = ($args -join ' ')
if ($env:WSLENV) { $env:WSLENV = "STUDGE_CMD:" + $env:WSLENV } else { $env:WSLENV = 'STUDGE_CMD' }

wsl.exe -d Ubuntu --cd $repoWsl -- bash scripts/wsl-run.sh
exit $LASTEXITCODE
