#!/usr/bin/env bash
# ==============================================================================
# SecuredStorage - CLI Release Automation Script
#
# Usage:
#   ./scripts/release.sh                      # Auto-detects version & notes from Cargo.toml + CHANGELOG.md
#   ./scripts/release.sh "Custom Title"       # Custom title with auto notes from CHANGELOG.md
#   ./scripts/release.sh "Title" "Notes"      # Custom title and custom notes
# ==============================================================================

set -euo pipefail

# Ensure script is run from project root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# 1. Ensure user email and name are configured
CURRENT_EMAIL=$(git config user.email || true)
if [ "$CURRENT_EMAIL" != "334075393+rituparnaprof@users.noreply.github.com" ]; then
  git config user.name "Rituparna Ghosh"
  git config user.email "334075393+rituparnaprof@users.noreply.github.com"
  echo "✔ Configured git author: Rituparna Ghosh <334075393+rituparnaprof@users.noreply.github.com>"
fi

# 2. Extract latest version from Cargo.toml
CARGO_TOML="$REPO_ROOT/src-tauri/Cargo.toml"
if [ ! -f "$CARGO_TOML" ]; then
  echo "❌ Error: Could not find $CARGO_TOML"
  exit 1
fi

VERSION=$(grep '^version = ' "$CARGO_TOML" | head -n 1 | cut -d '"' -f 2)
if [ -z "$VERSION" ]; then
  echo "❌ Error: Failed to parse version from $CARGO_TOML"
  exit 1
fi

TAG="v$VERSION"
TITLE="${1:-SecuredStorage $TAG}"

# 3. Extract release notes from CHANGELOG.md if not explicitly passed
if [ "${2:-}" != "" ]; then
  NOTES="$2"
else
  NOTES=$(python3 -c "
import re, os, sys
ver = '$VERSION'
if os.path.exists('CHANGELOG.md'):
    with open('CHANGELOG.md', 'r', encoding='utf-8') as f:
        text = f.read()
    m = re.search(rf'## \[{re.escape(ver)}\][^\n]*\n(.*?)(?=\n## \[|\Z)', text, re.DOTALL)
    if m:
        print(m.group(1).strip())
        sys.exit(0)
print('SecuredStorage release ' + '$TAG')
")
fi

echo "================================================================="
echo "  SecuredStorage Release Automation"
echo "================================================================="
echo "  Tag:       $TAG"
echo "  Title:     $TITLE"
echo "  Author:    $(git config user.name) <$(git config user.email)>"
echo "================================================================="
echo ""
echo "Release Notes:"
echo "-----------------------------------------------------------------"
echo "$NOTES"
echo "-----------------------------------------------------------------"
echo ""

# 4. Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
  echo "⚠️ Warning: You have uncommitted working tree changes."
  echo "Please commit or stash your changes before releasing."
  exit 1
fi

# 5. Create or update annotated git tag
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Notice: Tag $TAG already exists locally. Updating tag to current HEAD..."
  git tag -d "$TAG" >/dev/null
fi

git tag -a "$TAG" -m "$TITLE" -m "$NOTES"
echo "✔ Created annotated tag: $TAG"

# 6. Push to remote
echo "🚀 Pushing branch 'main' and tag '$TAG' to origin..."
git push origin main
git push origin "$TAG"

echo ""
echo "🎉 Release $TAG successfully pushed!"
echo "GitHub Actions is now compiling multi-platform binaries and will publish the release."
