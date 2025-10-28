#!/bin/bash

set -e

# Allow passing a specific commit-ish to compare against.
# Usage: ./compare_help_output.sh [<commit-ish>]

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $0 [<commit-ish>]"
    echo "If no commit is provided, defaults to HEAD~1."
    exit 0
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
PREVIOUS_COMMIT=${1:-HEAD~1}

echo "Current branch: $CURRENT_BRANCH"
echo "Comparing with commit: $PREVIOUS_COMMIT"

# Capture current version help output
echo ""
echo "=== Capturing CURRENT version help output ==="
cargo build --quiet 2>&1 | grep -v "warning:" || true
./capture_help_output.sh help_command_output/current

# Stash current changes if any
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo ""
    echo "=== Stashing current changes ==="
    git stash push -m "Temporary stash for help comparison"
    STASHED=1
else
    STASHED=0
fi

# Checkout previous commit (or specified commit)
echo ""
echo "=== Checking out PREVIOUS version ($PREVIOUS_COMMIT) ==="
git checkout "$PREVIOUS_COMMIT" --quiet

# Build previous version
echo ""
echo "=== Building PREVIOUS version ==="
cargo build --quiet 2>&1 | grep -v "warning:" || true

# Capture previous version help output
echo ""
echo "=== Capturing PREVIOUS version help output ==="
./capture_help_output.sh help_command_output/previous

# Return to current branch
echo ""
echo "=== Returning to current branch ==="
git checkout "$CURRENT_BRANCH" --quiet

# Restore stashed changes if any
if [ "$STASHED" -eq 1 ]; then
    echo "=== Restoring stashed changes ==="
    git stash pop --quiet
fi

# Compare the outputs
echo ""
echo "=========================================="
echo "=== COMPARING HELP OUTPUTS ==="
echo "=========================================="
echo ""

DIFFERENCES_FOUND=0

for file in help_command_output/current/*.txt; do
    filename=$(basename "$file")
    previous_file="help_command_output/previous/$filename"
    
    if [ ! -f "$previous_file" ]; then
        echo "❌ NEW FILE: $filename (not in previous version)"
        DIFFERENCES_FOUND=1
        continue
    fi
    
    if diff -q "$file" "$previous_file" > /dev/null 2>&1; then
        echo "✅ $filename - IDENTICAL"
    else
        echo "⚠️  $filename - DIFFERENCES FOUND"
        echo "   Running detailed diff:"
        diff -u "$previous_file" "$file" | head -50 || true
        echo ""
        DIFFERENCES_FOUND=1
    fi
done

# Check for removed files
echo ""
for file in help_command_output/previous/*.txt; do
    filename=$(basename "$file")
    current_file="help_command_output/current/$filename"
    
    if [ ! -f "$current_file" ]; then
        echo "❌ REMOVED FILE: $filename (was in previous version)"
        DIFFERENCES_FOUND=1
    fi
done

echo ""
echo "=========================================="
if [ "$DIFFERENCES_FOUND" -eq 0 ]; then
    echo "✅ ALL HELP OUTPUTS ARE IDENTICAL!"
else
    echo "⚠️  SOME DIFFERENCES FOUND (see above)"
fi
echo "=========================================="
