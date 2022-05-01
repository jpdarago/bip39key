#!/usr/bin/env bash

set -euo pipefail

export REALNAME="Satoshi Nakamoto"
export EMAIL="satoshin@gmx.com"
export USERID="$REALNAME <$EMAIL>"
export KEYID="7AF9E5EF4F47F53A74F70271D5B79D8F0BA42B12"

export BIP_39_1="legal winner thank year wave sausage worth useful legal winner thank yellow"
export BIP_39_2="letter advice cage absurd amount doctor acoustic avoid letter advice cage above"

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
echo "$BIP_39_1" | ./target/debug/bip39gpg -u "$USERID" | tee "$homedir/key.asc" | test_gpg --import
test_gpg --list-keys | grep -q "$USERID" || die "Key for $USERID not found"
test_gpg --list-keys | grep -q "$KEYID" || die "Key with Key ID $KEYID not found"
success

echo -n "Encrypt, and decrypt after reimporting"
export VALUE="$RANDOM"
echo "Message - $VALUE" > "$homedir/message.txt"
test_gpg --trust-model always --recipient "$REALNAME" --encrypt "$homedir/message.txt"
test_gpg --batch --yes --delete-secret-keys "$KEYID"
test_gpg --batch --yes --delete-keys "$KEYID"
echo "$BIP_39_1" | ./target/debug/bip39gpg -u "$USERID" | tee "$homedir/key.asc" | test_gpg --import
rm -rf "$homedir/message.txt"
test_gpg --decrypt "$homedir/message.txt.gpg" | grep -q "Message - $VALUE" || die "Message incorrectly decrypted"
success
