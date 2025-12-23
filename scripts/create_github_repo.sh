#!/usr/bin/env bash
# Script to create a GitHub repo and push the current project.
# Usage: ./scripts/create_github_repo.sh <repo-name> [public|private]

REPO_NAME=${1:-secure-file-share}
VISIBILITY=${2:-public}
DESCRIPTION=${3:-"Secure file-share demo (AES-256, KMS, CI)"}

if command -v gh >/dev/null 2>&1; then
  echo "Using gh CLI to create repo..."
  gh repo create "$REPO_NAME" --$VISIBILITY --source=. --remote=origin --push --description "$DESCRIPTION"
  echo "Done."
  exit 0
fi

if [ -z "$GITHUB_TOKEN" ]; then
  echo "ERROR: gh CLI not found and GITHUB_TOKEN not set. Install gh or set GITHUB_TOKEN." >&2
  exit 1
fi

# Create via REST API
API_JSON=$(jq -n --arg name "$REPO_NAME" --arg desc "$DESCRIPTION" --argjson priv $( [ "$VISIBILITY" = "private" ] && echo true || echo false ) '{name: $name, description: $desc, private: $priv}')

RESP=$(curl -s -H "Authorization: token $GITHUB_TOKEN" -H "User-Agent: create-script" -d "$API_JSON" https://api.github.com/user/repos)
CLONE_URL=$(echo "$RESP" | jq -r .clone_url)
HTML_URL=$(echo "$RESP" | jq -r .html_url)

if [ "$CLONE_URL" = "null" ]; then
  echo "Failed to create repo: $RESP" >&2
  exit 1
fi

git remote add origin "$CLONE_URL" || true
git branch -M main
git push -u origin main

echo "Repo created: $HTML_URL"