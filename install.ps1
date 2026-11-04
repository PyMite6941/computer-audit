# install.ps1 - Windows PowerShell setup
# Creates a Python venv, installs deps, optional npm install.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $Root

Write-Host "[computer-audit] Creating Python virtual environment..."
python -m venv venv

Write-Host "[computer-audit] Activating venv..."
& "$Root/venv/Scripts/Activate.ps1"

Write-Host "[computer-audit] Installing Python dependencies..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if (Get-Command npm -ErrorAction SilentlyContinue) {
  Write-Host "[computer-audit] npm detected; installing frontend deps (optional)..."
  npm install
} else {
  Write-Host "[computer-audit] npm not found; skipping frontend (install Node later if needed)"
}

Write-Host "[computer-audit] Setup complete. Run: .\run.ps1"
