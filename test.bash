#!/usr/bin/env bash

set -euo pipefail
umask 077

export REALNAME="Satoshi Nakamoto"
export EMAIL="satoshin@gmx.com"
export USERID="$REALNAME <$EMAIL>"
export KEYID="E3CF60B9A20DC3759FADCA2157E57457587213E6"

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

delete_keys() {
    local keyid="$1"
    test_gpg --batch --yes --delete-secret-keys "$keyid"
    test_gpg --batch --yes --delete-keys "$keyid"
}

import_key() {
    local bip39="$1"
    echo "$bip39" | ./target/debug/bip39gpg -u "$USERID" | tee "$homedir/key.asc" | test_gpg --import
}

echo -n "Building project"
cargo build --quiet
success

echo -n "Build key"
import_key "$BIP_39_1"
success

echo -n "Import a key into PGP"
test_gpg --import < "$homedir/key.asc"
test_gpg --list-keys | grep -q "$USERID" || die "Key for $USERID not found"
test_gpg --list-keys | grep -q "$KEYID" || die "Key with Key ID $KEYID not found"
delete_keys "$KEYID"
success

echo -n "Verify signatures"
test_gpg --import < "$homedir/key.asc"
export VALUE="$RANDOM"
echo "Message - $VALUE" > "$homedir/message.txt"
test_gpg --output "$homedir/message.sig" --detach-sig --sign "$homedir/message.txt"
delete_keys "$KEYID"
import_key "$BIP_39_1"
test_gpg --verify "$homedir/message.sig" "$homedir/message.txt" 2> /dev/null > /dev/null
rm -rf "$homedir/message.txt" "$homedir/message.sig"
success

rm -rf "$homedir/message.txt"

echo -n "Encrypt, and decrypt after reimporting"
test_gpg --import < "$homedir/key.asc"
echo "Message - $VALUE" > "$homedir/message.txt"
test_gpg --trust-model always --recipient "$REALNAME" --encrypt "$homedir/message.txt"
delete_keys "$KEYID"
echo "$BIP_39_1" | ./target/debug/bip39gpg -u "$USERID" | tee "$homedir/key.asc" | test_gpg --import
rm -rf "$homedir/message.txt"
test_gpg --decrypt "$homedir/message.txt.gpg" | grep -q "Message - $VALUE" || die "Message incorrectly decrypted"
delete_keys "$KEYID"
success

echo -n "SSH key"
echo "$BIP_39_1" | ./target/debug/bip39gpg -u "$USERID" -f ssh > "$homedir/id_ed25519"
ssh-keygen -v -y -P '' -f "$homedir/id_ed25519" 2>&1 > /dev/null || die "Invalid key"
success
