#!/usr/bin/env bash
set -euo pipefail

# --- CONFIG ---
PKG_NAME="cisco-hashgen"
PYPI_URL="https://upload.pypi.org/legacy/"

# Colors
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

# --- HELP ---
usage() {
    echo "Usage: $0 [--dry-run] [--no-delete]"
    exit 1
}

DRY_RUN=false
DELETE_BRANCH=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --no-delete) DELETE_BRANCH=false ;;
        *) usage ;;
    esac
    shift
done

# --- FUNCTIONS ---
log() { echo -e "${BOLD}$1${RESET}"; }
ok() { echo -e "${GREEN}✔${RESET} $1"; }
fail() { echo -e "${RED}✖${RESET} $1" >&2; exit 1; }

# Ensure we're in a venv
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    fail "Not in a virtual environment. Activate one first."
fi

# Get version from __init__.py
VERSION=$(grep '__version__' src/${PKG_NAME//-/_}/__init__.py | sed -E 's/.*"([^"]+)".*/\1/')
if [[ -z "$VERSION" ]]; then
    fail "Could not determine version from __init__.py"
fi
BRANCH="release/v${VERSION}"
TAG="v${VERSION}"

log "🚀 Preparing release $TAG"

# Check branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" != "$BRANCH" ]]; then
    fail "You must be on branch $BRANCH (currently on $CURRENT_BRANCH)"
fi

# Check working tree clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    fail "Working tree not clean. Commit or stash changes first."
fi

# Build
log "📦 Building package"
rm -rf dist/ build/
python3 -m build
ok "Build complete"

# Upload to PyPI
log "📤 Uploading to PyPI ($PYPI_URL)"
if $DRY_RUN; then
    echo "(dry run) twine upload dist/*"
else
    python3 -m twine upload --non-interactive dist/*
fi
ok "PyPI upload complete"

# Create/update GitHub release
log "🏷 Creating GitHub release $TAG"
NOTES_FILE="docs/releases/release-notes-${VERSION}.md"
if [[ ! -f "$NOTES_FILE" ]]; then
    fail "Release notes file not found: $NOTES_FILE"
fi

if $DRY_RUN; then
    echo "(dry run) git tag -a $TAG -m \"Release $TAG\""
    echo "(dry run) git push origin $BRANCH"
    echo "(dry run) git push origin $TAG"
    echo "(dry run) gh release create $TAG --title \"$PKG_NAME $TAG\" --notes-file \"$NOTES_FILE\""
else
    git tag -a "$TAG" -m "Release $TAG"
    git push origin "$BRANCH"
    git push origin "$TAG"
    gh release create "$TAG" --title "$PKG_NAME $TAG" --notes-file "$NOTES_FILE"
    gh release upload "$TAG" dist/*.whl dist/*.tar.gz --clobber
fi
ok "GitHub release created"

# Merge into main
log "🔀 Merging into main"
if $DRY_RUN; then
    echo "(dry run) git checkout main && git merge --ff-only $BRANCH && git push origin main"
else
    git checkout main
    git merge --ff-only "$BRANCH"
    git push origin main
fi
ok "Main updated"

# Delete branch
if $DELETE_BRANCH; then
    log "🧹 Deleting release branch"
    if $DRY_RUN; then
        echo "(dry run) git branch -d $BRANCH && git push origin --delete $BRANCH"
    else
        git branch -d "$BRANCH"
        git push origin --delete "$BRANCH"
    fi
    ok "Branch deleted"
fi

log "✅ Release $TAG complete"
