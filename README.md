# PCSuite

[![CI](https://github.com/LogunLACC/PCSuite/actions/workflows/ci.yml/badge.svg)](https://github.com/LogunLACC/PCSuite/actions/workflows/ci.yml)

A modular PC cleaner and optimizer suite for Windows.

## Features
- Cleaning Windows temp files, browser caches, update leftovers
- Startup and service management
- Security and optimization tools
- Rich CLI and TUI
 - Firewall status/toggle, Defender scan, file reputation check
 - Network stack and power plan tuning (what-if/apply)

## Structure
See the `pcsuite/src/pcsuite/` directory for modules.

## Quick Start (from source)
- Prereqs: Python 3.11+ on Windows.
- Create venv and install deps (PowerShell):

```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install typer rich psutil pywin32 pyyaml
```

- Run the CLI from source (module):

```
$env:PYTHONPATH = (Resolve-Path "pcsuite/src").Path
python -m pcsuite.cli.main --help
```

- Or install the package locally and use the `pcsuite` command:

```
cd pcsuite
pip install -e .
pcsuite --help
pcsuite ui gui   # launch GUI
pcsuite-ui       # or use the direct GUI command
```

## Examples
- Preview cleanup targets (writes audit JSON under `reports/`):

```
pcsuite clean preview --category temp,browser,dumps,do,recycle

# Non-admin user-only scope (safe on roaming profiles):
pcsuite clean preview --scope user --category temp,browser,dumps
```

- Run cleanup (moves files into quarantine under `reports/`):

```
pcsuite clean run --category temp,browser,dumps,do,recycle

# Non-admin user-only scope (safe on roaming profiles):
pcsuite clean run --scope user --category temp,browser,dumps --yes
```

- Roll back (restore from latest rollback file):

```
pcsuite clean rollback
```

- Purge quarantine (permanent delete to free space):

```
# Delete latest quarantine run (cannot be undone)
pcsuite clean purge --yes

# Or delete all quarantine runs older than 7 days
pcsuite clean purge --older-than 7 --yes

# Or purge everything in quarantine
pcsuite clean purge --all --yes
```

- Registry cleaner (backs up keys before cleanup):

```
pcsuite registry preview
pcsuite registry run --dry-run
pcsuite registry run --yes
pcsuite registry rollback --yes
```

- Drivers via Windows Update and pnputil:

```
pcsuite drivers list
pcsuite drivers scan
pcsuite drivers update --dry-run
pcsuite drivers update --yes
```

- Processes and services:

```
pcsuite process list --limit 20
pcsuite process kill --pid 1234 --dry-run
pcsuite services list --status running
```

- Tasks and scheduling:

```
pcsuite tasks list
pcsuite schedule create --name \MyTasks\PCSuiteCleanup --when DAILY --command "pcsuite clean run --category temp" --dry-run
pcsuite schedule delete --name \MyTasks\PCSuiteCleanup --dry-run
```

- Optimize profiles:

```
pcsuite optimize list-profiles
pcsuite optimize apply default --dry-run
pcsuite optimize apply default --yes

- Network stack tuning (what-if/apply):

```
pcsuite optimize net            # show recommended TCP settings
pcsuite optimize net --apply    # apply via netsh
```

- Power plan switching:

```
pcsuite optimize power-plan --profile high        # dry-run prints command
pcsuite optimize power-plan --profile high --apply
```
```

## Command Reference
- Clean:
  - Preview: `pcsuite clean preview [--scope auto|user|all] --category temp,browser,dumps,do,recycle`
  - Run: `pcsuite clean run [--scope auto|user|all] --category <list> [--dry-run] [--yes]`
  - Rollback: `pcsuite clean rollback [--dry-run] [--yes]`
  - Purge quarantine: `pcsuite clean purge [--run <name>|latest] [--older-than N] [--all] [--dry-run] [--yes]`

- Registry:
  - Preview: `pcsuite registry preview`
  - Run: `pcsuite registry run [--dry-run] [--yes]`
  - Rollback: `pcsuite registry rollback [--file <manifest>] [--dry-run] [--yes]`

- Drivers:
  - List installed: `pcsuite drivers list`
  - Scan for updates: `pcsuite drivers scan`
  - Start install: `pcsuite drivers update [--dry-run] [--yes]`

- Services:
  - List: `pcsuite services list [--status running|stopped]`

- Process:
  - Top by memory: `pcsuite process list [--limit N]`
  - Kill: `pcsuite process kill --pid <PID> [--dry-run] [--yes]`

- System:
  - Info: `pcsuite system info`
  - Drives: `pcsuite system drives`

- Tasks:
  - List: `pcsuite tasks list`

- Schedule:
  - List: `pcsuite schedule list`
  - Create: `pcsuite schedule create --name <Name> --when DAILY --command "pcsuite ..." [--dry-run] [--yes]`
  - Delete: `pcsuite schedule delete --name <Name> [--dry-run] [--yes]`

- Optimize:
  - List: `pcsuite optimize list-profiles`
  - Apply: `pcsuite optimize apply <profile> [--dry-run] [--yes]`

- Security:
  - Check: `pcsuite security check`
  - Audit posture: `pcsuite security audit`
  - List listening ports: `pcsuite security ports [--limit N]`
  - Start Defender scan: `pcsuite security defender-scan [--quick/--no-quick]`
  - Harden (what-if): `pcsuite security harden`
  - Harden (apply): `pcsuite security harden --apply --yes`
  - Harden minimal (what-if): `pcsuite security harden --profile minimal`
  - Harden minimal (apply): `pcsuite security harden --profile minimal --apply --yes`
  - With Explorer restart prompt (minimal): `pcsuite security harden --profile minimal --apply --restart-explorer`
  - Firewall status/toggle: `pcsuite security firewall [--enable/--no-enable] [--dry-run]`
  - File reputation: `pcsuite security reputation <path>`

## Convenience Scripts (PowerShell)
- Preview: `./pcsuite/scripts/preview.ps1 -Category "temp,browser"`
- Cleanup: `./pcsuite/scripts/cleanup.ps1 -Category "temp,browser" [-DryRun]`
- Rollback: `./pcsuite/scripts/rollback.ps1 [-File "reports/rollback_YYYYMMDD-HHMMSS.json"] [-DryRun]`

## Safety
- Quarantine first: Cleanup moves files to `reports/quarantine/<timestamp>/` and writes `rollback_*.json`. No permanent deletion in the default flow.
- Rollback: `clean rollback` restores from quarantine using the mapping file.
- Purge: Use `clean purge` to permanently delete quarantined files once you've reviewed reports and no rollback is needed.
- Dry-run: Add `--dry-run` to `clean run` or `clean rollback` to simulate without changing files (reports are still written).
- Prompts: Destructive operations prompt for confirmation by default. Use `--yes` to skip prompts in non-dry-run mode.
- Permissions: Some targets may require elevated PowerShell (Run as Administrator) to move.
- User scope: Use `--scope user` to restrict cleanup to user-writable locations only (e.g., `%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%`). This mode avoids system paths like `C:\Windows`, `C:\ProgramData`, and multi-user recycle bins and is recommended when you cannot elevate (e.g., roaming profiles).
- Scope: Signatures target caches/temp/dumps; exclusions protect system directories. Always review the preview table before running cleanup.

## Notes
- Data files live in `pcsuite/src/pcsuite/data/` (`signatures.yml`, `exclusions.yml`). Populate these to see real preview results.
 - Optimize profiles live in `pcsuite/src/pcsuite/data/optimize_profiles.yml` and support simple `reg_set` steps.
