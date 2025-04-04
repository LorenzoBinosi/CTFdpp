#!/bin/bash

set -e

CTFD_DIR="CTFd"
PATCH_FILE="../solves_only.patch"

cd "$CTFD_DIR"

# Check if the patch is already applied:
if git apply --reverse --check "$PATCH_FILE" > /dev/null 2>&1; then
    echo "Patch has already been applied. Skipping."
else
    # Ensure that the patch can be applied cleanly
    if git apply --check "$PATCH_FILE" > /dev/null 2>&1; then
        git apply "$PATCH_FILE"
        echo "Patch applied successfully."
    else
        echo "Patch cannot be applied cleanly. Please resolve conflicts manually."
        ERROR_OUTPUT=$(git apply --check "$PATCH_FILE" 2>&1) || true
        echo "$ERROR_OUTPUT"
        exit 1
    fi
fi
