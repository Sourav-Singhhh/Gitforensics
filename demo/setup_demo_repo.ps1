<#
.SYNOPSIS
  Deterministic demo fixture setup for GitForensics live presentation.
.DESCRIPTION
  Generates a synthetic Git repository demonstrating ACTIVE, HISTORICAL,
  and ZOMBIE secret exposure states, as well as OFS_DELTA packed objects.
  Uses 100% synthetic/dummy credentials only.
#>

param(
    [string]$TargetDir = "./demo_repo"
)

$ErrorActionPreference = "Stop"

# Safety validation on target directory
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    Write-Error "Error: Target directory cannot be empty."
    exit 1
}

$trimmed = $TargetDir.Trim()
if ($trimmed -eq "." -or $trimmed -eq ".." -or $trimmed -eq "/" -or $trimmed -eq "\" -or $trimmed -eq "C:\" -or $trimmed -eq "c:\") {
    Write-Error "Error: Target directory cannot be root, '.', or '..'."
    exit 1
}

$absTarget = [System.IO.Path]::GetFullPath($TargetDir)
$currentDir = [System.IO.Path]::GetFullPath((Get-Location).Path)

if ($absTarget -eq $currentDir) {
    Write-Error "Error: Target directory cannot be the current working directory."
    exit 1
}

$driveRoot = [System.IO.Path]::GetPathRoot($absTarget)
if ($absTarget -eq $driveRoot) {
    Write-Error "Error: Target directory cannot be a drive root directory."
    exit 1
}

if (Test-Path $absTarget) {
    Remove-Item -Recurse -Force $absTarget
}
New-Item -ItemType Directory -Path $absTarget -Force | Out-Null

Write-Host "Creating deterministic demo repository at: $absTarget"

# 1. Initialize repo
git -C $absTarget init -b main
git -C $absTarget config user.name "Alice Security"
git -C $absTarget config user.email "alice@example.com"

# 2. Commit 1 on main (ACTIVE): app.env with Slack Token
$slackPrefix = "xoxb"
$slackToken = "$slackPrefix-012345678901-0123456789012-0123456789abcdefghijklmn"
Set-Content -Path (Join-Path $absTarget "app.env") -Value "SLACK_BOT_TOKEN=$slackToken"
git -C $absTarget add app.env
git -C $absTarget commit -m "Initial commit with active app config"

# 3. Branch legacy-creds (HISTORICAL): deploy.env with AWS Key (not reachable from main HEAD)
git -C $absTarget checkout -b legacy-creds
$awsPrefix = "AKIA"
$histAWS = "${awsPrefix}9876543210FEDCBA"
Set-Content -Path (Join-Path $absTarget "deploy.env") -Value "AWS_ACCESS_KEY_ID=$histAWS"
git -C $absTarget add deploy.env
git -C $absTarget commit -m "Add legacy deploy credentials"

# 4. Switch back to main (so deploy.env is NOT reachable from main HEAD)
git -C $absTarget checkout main

# 5. Commit on main and amend (ZOMBIE): unreferenced loose blob
$zombieAWS = "${awsPrefix}1111222233334444"
Set-Content -Path (Join-Path $absTarget "zombie_leak.txt") -Value "AWS_SECRET_KEY=$zombieAWS"
git -C $absTarget add zombie_leak.txt
git -C $absTarget commit -m "Accidental secret commit"

Set-Content -Path (Join-Path $absTarget "zombie_leak.txt") -Value "clean configuration payload"
git -C $absTarget add zombie_leak.txt
git -C $absTarget commit --amend -m "Clean amended commit on main"

# 6. Repack to create PACK v2 with OFS_DELTA objects
git -C $absTarget repack -a -d

Write-Host "`n=== DEMO FIXTURE READY ==="
Write-Host "Try running:"
Write-Host "  gitforensics scan $absTarget"
Write-Host "  gitforensics scan $absTarget --json"
