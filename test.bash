#!/usr/bin/env bash

set -euo pipefail

export REALNAME="Satoshi Nakamoto"
export EMAIL="satoshin@gmx.com"
export USERID="$REALNAME <$EMAIL>"

export BIP_39_1="legal winner thank year wave sausage worth useful legal winner thank yellow"

# Set up a separate environment for GPG.
homedir="$(mktemp -d homedir.XXXXXX)"
chmod 700 "$homedir"
cleanup() {
    rm -rf "$homedir"
}
trap cleanup INT TERM EXIT

test_gpg() {
    gpg --quiet --homedir "$homedir" "$@"
}

die() {
    echo "$(tput setaf 1)Failed test: $@$(tput sgr 0)"
    exit 1
}

success() {
    echo ": $(tput setaf 2)OK$(tput sgr 0)"
}

echo -n "Building project"
cargo build --quiet
success

echo -n "Import a key into PGP"
echo "$BIP_39_1" | ./target/debug/bip39gpg -u "$USERID" | test_gpg --import
test_gpg --list-keys | grep -q "$USERID" || die "Key not found"
success
