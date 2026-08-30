#!/usr/bin/env bash
# Deterministic demo fixture setup for GitForensics live presentation.
# Generates a synthetic Git repository demonstrating ACTIVE, HISTORICAL,
# and ZOMBIE secret exposure states, as well as OFS_DELTA packed objects.
# Uses 100% synthetic/dummy credentials only.

set -euo pipefail

TARGET_ARG="${1:-./demo_repo}"

# Safety validation on target directory
if [ -z "$TARGET_ARG" ] || [ "$TARGET_ARG" = "." ] || [ "$TARGET_ARG" = ".." ] || [ "$TARGET_ARG" = "/" ] || [ "$TARGET_ARG" = "~" ]; then
  echo "Error: Target directory cannot be root, home, current directory (.), or parent (..)." >&2
  exit 1
fi

CURRENT_DIR="$(pwd)"
PARENT_DIR="$(cd "$(dirname "$TARGET_ARG")" 2>/dev/null && pwd)" || PARENT_DIR="$CURRENT_DIR"
BASE_NAME="$(basename "$TARGET_ARG")"
TARGET_DIR="${PARENT_DIR}/${BASE_NAME}"

if [ "$TARGET_DIR" = "$CURRENT_DIR" ] || [ "$TARGET_DIR" = "/" ] || [ "$TARGET_DIR" = "${HOME:-/root}" ]; then
  echo "Error: Target directory cannot be repository root, root (/), or home." >&2
  exit 1
fi

rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

export GIT_AUTHOR_NAME="Alice Security"
export GIT_AUTHOR_EMAIL="alice@example.com"
export GIT_COMMITTER_NAME="Alice Security"
export GIT_COMMITTER_EMAIL="alice@example.com"

echo "Creating deterministic demo repository at: $TARGET_DIR"

# 1. Initialize repo
git -C "$TARGET_DIR" init -b main
git -C "$TARGET_DIR" config user.name "Alice Security"
git -C "$TARGET_DIR" config user.email "alice@example.com"

# 2. Commit 1 on main (ACTIVE): app.env with Slack Token
SLACK_PREFIX="xoxb"
SLACK_TOKEN="${SLACK_PREFIX}-012345678901-0123456789012-0123456789abcdefghijklmn"
echo "SLACK_BOT_TOKEN=${SLACK_TOKEN}" > "${TARGET_DIR}/app.env"
git -C "$TARGET_DIR" add app.env
git -C "$TARGET_DIR" commit -m "Initial commit with active app config"

# 3. Branch legacy-creds (HISTORICAL): deploy.env with AWS Key (not reachable from main HEAD)
git -C "$TARGET_DIR" checkout -b legacy-creds
AWS_PREFIX="AKIA"
HIST_AWS="${AWS_PREFIX}9876543210FEDCBA"
echo "AWS_ACCESS_KEY_ID=${HIST_AWS}" > "${TARGET_DIR}/deploy.env"
git -C "$TARGET_DIR" add deploy.env
git -C "$TARGET_DIR" commit -m "Add legacy deploy credentials"

# 4. Switch back to main (so deploy.env is NOT reachable from main HEAD)
git -C "$TARGET_DIR" checkout main

# 5. Commit on main and amend (ZOMBIE): unreferenced loose blob
ZOMBIE_AWS="${AWS_PREFIX}1111222233334444"
echo "AWS_SECRET_KEY=${ZOMBIE_AWS}" > "${TARGET_DIR}/zombie_leak.txt"
git -C "$TARGET_DIR" add zombie_leak.txt
git -C "$TARGET_DIR" commit -m "Accidental secret commit"

echo "clean configuration payload" > "${TARGET_DIR}/zombie_leak.txt"
git -C "$TARGET_DIR" add zombie_leak.txt
git -C "$TARGET_DIR" commit --amend -m "Clean amended commit on main"

# 6. Repack to create PACK v2 with OFS_DELTA objects
git -C "$TARGET_DIR" repack -a -d

echo ""
echo "=== DEMO FIXTURE READY ==="
echo "Try running:"
echo "  gitforensics scan $TARGET_DIR"
echo "  gitforensics scan $TARGET_DIR --json"
