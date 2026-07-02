$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
$BuildDir = "$ProjectDir\build_temp"

Write-Host "`n[+] Building highly portable vulnscan.pyz..." -ForegroundColor Cyan

# 1. Clean previous builds
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Path $BuildDir | Out-Null

# 2. Install dependencies into the build folder
Write-Host "[+] Bundling dependencies (click, pyyaml)..."
pip install -r "$ProjectDir\requirements.txt" --target $BuildDir -q

# 3. Copy source code
Write-Host "[+] Copying source code..."
Copy-Item -Path "$ProjectDir\core" -Destination $BuildDir -Recurse
Copy-Item -Path "$ProjectDir\modules" -Destination $BuildDir -Recurse
Copy-Item -Path "$ProjectDir\main.py" -Destination $BuildDir
Copy-Item -Path "$ProjectDir\allowlist.example.yaml" -Destination $BuildDir

# 4. Create __main__.py entry point
$MainContent = @"
import sys
import main

if __name__ == '__main__':
    sys.exit(main.main())
"@
Set-Content -Path "$BuildDir\__main__.py" -Value $MainContent

# 5. Build zipapp
Write-Host "[+] Compiling single-file executable (.pyz)..."
python -m zipapp $BuildDir -o "$ProjectDir\vulnscan.pyz" -p "/usr/bin/env python3"

# 6. Cleanup
Remove-Item -Recurse -Force $BuildDir

Write-Host "`n[SUCCESS] Created single-file portable scanner: vulnscan.pyz" -ForegroundColor Green
Write-Host "You can now drop this SINGLE FILE onto any Linux VM and run it directly!"
