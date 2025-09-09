param(
    [string]$Category = "temp,browser,dumps,do,recycle",
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$srcPath = (Resolve-Path (Join-Path $PSScriptRoot '..\src')).Path
$env:PYTHONPATH = $srcPath
Write-Host "Using PYTHONPATH=$srcPath" -ForegroundColor DarkGray

if ($DryRun) {
    python -m pcsuite.cli.main clean run --category $Category --dry-run
} else {
    python -m pcsuite.cli.main clean run --category $Category
}
