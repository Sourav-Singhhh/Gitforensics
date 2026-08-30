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

$absTarget = [System.IO.Path]::GetFullPath($TargetDir)
if (Test-Path $absTarget) {
    Remove-Item -Recurse -Force $absTarget
}
New-Item -ItemType Directory -Path $absTarget -Force | Out-Null

function run-git {
    param([string[]]$cmdArgs)
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "git"
    $pinfo.Arguments = ($cmdArgs -join " ")
    $pinfo.WorkingDirectory = $absTarget
    $pinfo.UseShellExecute = $false
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.EnvironmentVariables["GIT_AUTHOR_NAME"] = "Alice Security"
    $pinfo.EnvironmentVariables["GIT_AUTHOR_EMAIL"] = "alice@example.com"
    $pinfo.EnvironmentVariables["GIT_COMMITTER_NAME"] = "Alice Security"
    $pinfo.EnvironmentVariables["GIT_COMMITTER_EMAIL"] = "alice@example.com"
    $p = [System.Diagnostics.Process]::Start($pinfo)
    $p.WaitForExit()
}

Write-Host "Creating deterministic demo repository at: $absTarget"

# 1. Initialize repo
run-git @("init", "-b", "main")
run-git @("config", "user.name", "Alice Security")
run-git @("config", "user.email", "alice@example.com")

# 2. Commit 1: Active Secret (Slack Token constructed at runtime for demo)
$slackPrefix = "xoxb"
$slackToken = "$slackPrefix-012345678901-0123456789012-0123456789abcdefghijklmn"
Set-Content -Path (Join-Path $absTarget "app.env") -Value "SLACK_BOT_TOKEN=$slackToken"
run-git @("add", ".")
run-git @("commit", "-m", "Initial commit with config")

# 3. Commit 2: Historical Secret (AWS Key that will be deleted in next commit)
$awsPrefix = "AKIA"
$histAWS = "${awsPrefix}9876543210FEDCBA"
Set-Content -Path (Join-Path $absTarget "deploy.env") -Value "AWS_ACCESS_KEY_ID=$histAWS"
run-git @("add", ".")
run-git @("commit", "-m", "Add temporary deploy credentials")

# 4. Commit 3: Delete deploy.env (Making it HISTORICAL)
Remove-Item -Path (Join-Path $absTarget "deploy.env")
run-git @("add", ".")
run-git @("commit", "-m", "Remove deploy credentials from tree")

# 5. Commit 4: Create a secret and amend it immediately (Making it a ZOMBIE loose object)
$zombieAWS = "${awsPrefix}1111222233334444"
Set-Content -Path (Join-Path $absTarget "zombie_leak.txt") -Value "AWS_SECRET_KEY=$zombieAWS"
run-git @("add", ".")
run-git @("commit", "-m", "Accidental secret to amend")

# Overwrite and amend -> leaves loose blob unreferenced in .git/objects/
Set-Content -Path (Join-Path $absTarget "zombie_leak.txt") -Value "clean configuration payload"
run-git @("add", ".")
run-git @("commit", "--amend", "-m", "Clean amended commit")

# 6. Repack to create PACK v2 with OFS_DELTA objects
run-git @("repack", "-a", "-d")

Write-Host "`n=== DEMO FIXTURE READY ==="
Write-Host "Try running:"
Write-Host "  gitforensics scan $absTarget"
Write-Host "  gitforensics scan $absTarget --json"
