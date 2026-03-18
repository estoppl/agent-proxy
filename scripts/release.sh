#!/usr/bin/env bash
set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: ./scripts/release.sh <version>"
  echo "Example: ./scripts/release.sh 0.11.0"
  exit 1
fi

VERSION="$1"
TAG="v${VERSION}"

# Ensure we're on main and clean
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
  echo "Error: must be on main branch (currently on $BRANCH)"
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "Error: working directory is not clean"
  exit 1
fi

echo "Releasing ${TAG}..."

# Bump versions
sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
sed -i '' "s/\"version\": \".*\"/\"version\": \"${VERSION}\"/" npm/package.json

# Update Cargo.lock
cargo check --quiet

# Commit, tag, push
git add Cargo.toml Cargo.lock npm/package.json
git commit -m "Release ${TAG}"
git tag "${TAG}"
git push origin main
git push origin "${TAG}"

echo "Done! ${TAG} pushed — release pipeline running."
echo "Watch: https://github.com/estoppl/estoppl/actions"
