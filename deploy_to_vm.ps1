param (
    [Parameter(Mandatory=$true, HelpMessage="Enter the IP address of your Linux VM")]
    [string]$TargetIP,

    [Parameter(Mandatory=$true, HelpMessage="Enter your SSH username for the Linux VM")]
    [string]$Username
)

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot

Write-Host "`n[+] Preparing vulnscan for deployment..." -ForegroundColor Cyan

# 1. Create a zip archive of the project
$ZipFile = "$ProjectDir\vulnscan_deploy.zip"
if (Test-Path $ZipFile) { Remove-Item $ZipFile -Force }
Compress-Archive -Path "$ProjectDir\*" -DestinationPath $ZipFile -Force
Write-Host "[+] Project zipped successfully." -ForegroundColor Green

# 2. Transfer to the Linux VM
Write-Host "[+] Transferring to $Username@$TargetIP (You may be prompted for your SSH password)..." -ForegroundColor Cyan
scp $ZipFile "${Username}@${TargetIP}:/tmp/vulnscan_deploy.zip"

# 3. Extract and execute on the remote VM
Write-Host "[+] Extracting and running the scanner on the VM..." -ForegroundColor Cyan
$RemoteCommand = @"
    mkdir -p ~/vulnscan && \
    unzip -o /tmp/vulnscan_deploy.zip -d ~/vulnscan > /dev/null && \
    cd ~/vulnscan && \
    cp -n allowlist.example.yaml allowlist.yaml && \
    echo 'local_only: true' > allowlist.yaml && \
    sudo apt-get update -qq && \
    sudo apt-get install -y python3-pip python3-venv -qq > /dev/null && \
    python3 -m venv venv && \
    source venv/bin/activate && \
    pip install -r requirements.txt -q && \
    sudo ./venv/bin/python main.py
"@

ssh "${Username}@${TargetIP}" $RemoteCommand

Write-Host "`n[+] Scan Complete! Pulling reports back to Windows..." -ForegroundColor Cyan
if (!(Test-Path "$ProjectDir\final_reports")) { New-Item -ItemType Directory -Path "$ProjectDir\final_reports" | Out-Null }
scp -r "${Username}@${TargetIP}:~/vulnscan/reports/*" "$ProjectDir\final_reports/"

Write-Host "`n[SUCCESS] Reports downloaded to D:\Bug bounty\final_reports!" -ForegroundColor Green
Write-Host "Cleaning up deploy file..."
Remove-Item $ZipFile -Force
