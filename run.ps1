# run.ps1 - Windows PowerShell launcher
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $Root

if (-not (Test-Path "$Root/venv")) {
  Write-Host "Virtual env not found. Run .\install.ps1 first."
  exit 1
}

& "$Root/venv/Scripts/Activate.ps1"

$cmd = if ($args.Count -gt 0) { $args[0] } else { "" }
switch ($cmd) {
  "iam"   { python -m cli.main iam @$args[1..$args.Length] }
  "forensics" { python -m cli.main forensics @$args[1..$args.Length] }
  "api"   { python -m cli.main api @$args[1..$args.Length] }
  "audit" { python -m cli.main audit @$args[1..$args.Length] }
  "web"   { python -m cli.main web @$args[1..$args.Length] }
  "tui"   { python -m tui.app }
  default { python -m cli.main @$args }
}
