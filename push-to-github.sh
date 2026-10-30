#!/bin/sh
#
# Create the GitHub repository for this project and push it.
#
#   ./push-to-github.sh                     # public  github.com/Pandu49251/nexus-system-doctor
#   ./push-to-github.sh --private           # private instead
#   GH_USER=someone ./push-to-github.sh     # push elsewhere
#
# Requires the GitHub CLI (https://cli.github.com/) and 'gh auth login' once.
# Without gh it prints the equivalent manual commands instead of failing.
#
set -eu

GH_USER="${GH_USER:-Pandu49251}"
NAME=nexus-system-doctor
VISIBILITY=--public
[ "${1:-}" = "--private" ] && VISIBILITY=--private

cd "$(dirname "$0")"
URL="https://github.com/$GH_USER/$NAME"

if ! command -v gh >/dev/null 2>&1; then
    echo "gh (GitHub CLI) is not installed. Either:"
    echo "    sudo apt install gh && gh auth login && $0"
    echo "or push manually:"
    echo "    git remote add origin $URL.git"
    echo "    git push -u origin main --tags"
    exit 1
fi

gh repo create "$GH_USER/$NAME" "$VISIBILITY" --source=. --push
echo
echo "Repository :  $URL"
echo "Actions    :  $URL/actions"
echo "Release    :  gh release create v1.0.0 dist/*.deb --generate-notes"
echo "             ($URL/releases)"
