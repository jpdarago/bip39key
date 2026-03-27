#!/usr/bin/env bash
set -euo pipefail

# Check that the latest git tag, Cargo.toml version, and Cargo.lock version all match.

CARGO_TOML_VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
CARGO_LOCK_VERSION=$(grep -A1 'name = "bip39key"' Cargo.lock | grep version | sed 's/.*"\(.*\)"/\1/')
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "no tags")
TAG_VERSION="${LATEST_TAG#v}"

errors=0

if [ "$CARGO_TOML_VERSION" != "$CARGO_LOCK_VERSION" ]; then
    echo "MISMATCH: Cargo.toml ($CARGO_TOML_VERSION) != Cargo.lock ($CARGO_LOCK_VERSION)"
    echo "  Run 'cargo check' to update Cargo.lock"
    errors=1
fi

if [ "$LATEST_TAG" = "no tags" ]; then
    echo "WARNING: No git tags found, skipping tag check"
elif [ "$CARGO_TOML_VERSION" != "$TAG_VERSION" ]; then
    echo "MISMATCH: Cargo.toml ($CARGO_TOML_VERSION) != latest tag ($LATEST_TAG)"
    echo "  Either update Cargo.toml or create a new tag"
    errors=1
fi

if [ "$errors" -eq 0 ]; then
    echo "OK: All versions match ($CARGO_TOML_VERSION)"
fi

exit $errors
