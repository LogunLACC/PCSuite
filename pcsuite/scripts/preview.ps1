param(
    [string]$Category = "temp,browser,dumps,do,recycle"
)

$ErrorActionPreference = 'Stop'
$srcPath = (Resolve-Path (Join-Path $PSScriptRoot '..\src')).Path
$env:PYTHONPATH = $srcPath
Write-Host "Using PYTHONPATH=$srcPath" -ForegroundColor DarkGray

python -m pcsuite.cli.main clean preview --category $Category

