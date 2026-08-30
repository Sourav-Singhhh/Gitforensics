#!/usr/bin/env bash
# Deterministic demo fixture setup for GitForensics live presentation.
# Generates a synthetic Git repository demonstrating ACTIVE, HISTORICAL,
# and ZOMBIE secret exposure states, as well as OFS_DELTA packed objects.
# Uses 100% synthetic/dummy credentials only.

set -euo pipefail

TARGET_DIR="${1:-./demo_repo}"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

export GIT_AUTHOR_NAME="Alice Security"
export GIT_AUTHOR_EMAIL="alice@example.com"
export GIT_COMMITTER_NAME="Alice Security"
export GIT_COMMITTER_EMAIL="alice@example.com"

echo "Creating deterministic demo repository at: $TARGET_DIR"

git init -b main
git config user.name "Alice Security"
git config user.email "alice@example.com"

# 1. Commit 1: Active Secret (Slack Token constructed at runtime for demo)
SLACK_PREFIX="xoxb"
SLACK_TOKEN="${SLACK_PREFIX}-012345678901-0123456789012-0123456789abcdefghijklmn"
echo "SLACK_BOT_TOKEN=${SLACK_TOKEN}" > app.env
git add . && git commit -m "Initial commit with config"

# 2. Commit 2: Historical Secret (AWS Key that will be deleted)
AWS_PREFIX="AKIA"
HIST_AWS="${AWS_PREFIX}9876543210FEDCBA"
echo "AWS_ACCESS_KEY_ID=${HIST_AWS}" > deploy.env
git add . && git commit -m "Add temporary deploy credentials"

# 3. Commit 3: Delete deploy.env (Making it HISTORICAL)
rm deploy.env
git add . && git commit -m "Remove deploy credentials from tree"

# 4. Commit 4: Create a secret and amend it immediately (Making it a ZOMBIE loose object)
ZOMBIE_AWS="${AWS_PREFIX}1111222233334444"
echo "AWS_SECRET_KEY=${ZOMBIE_AWS}" > zombie_leak.txt
git add . && git commit -m "Accidental secret to amend"

echo "clean configuration payload" > zombie_leak.txt
git add . && git commit --amend -m "Clean amended commit"

# 5. Repack to create PACK v2 with OFS_DELTA objects
git repack -a -d

echo ""
echo "=== DEMO FIXTURE READY ==="
echo "Try running:"
echo "  gitforensics scan $TARGET_DIR"
echo "  gitforensics scan $TARGET_DIR --json"
