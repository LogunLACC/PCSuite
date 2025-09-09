param(
    [string]$File = "",
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$srcPath = (Resolve-Path (Join-Path $PSScriptRoot '..\src')).Path
$env:PYTHONPATH = $srcPath
Write-Host "Using PYTHONPATH=$srcPath" -ForegroundColor DarkGray

if ([string]::IsNullOrWhiteSpace($File)) {
    if ($DryRun) {
        python -m pcsuite.cli.main clean rollback --dry-run
    } else {
        python -m pcsuite.cli.main clean rollback
    }
} else {
    if ($DryRun) {
        python -m pcsuite.cli.main clean rollback --file $File --dry-run
    } else {
        python -m pcsuite.cli.main clean rollback --file $File
    }
}
