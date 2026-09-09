#compdef bip39key

autoload -U is-at-least

_bip39key() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'-u+[RFC 2822 of the user, e.g. "User <user@email.com>". Required unless --from-receipt is set]:USER_ID:_default' \
'--user-id=[RFC 2822 of the user, e.g. "User <user@email.com>". Required unless --from-receipt is set]:USER_ID:_default' \
'-i+[Filename from which to read the mnemonic words]:INPUT_FILENAME:_default' \
'--input-filename=[Filename from which to read the mnemonic words]:INPUT_FILENAME:_default' \
'-o+[Filename where to output the keys, if not present then write to stdout]:OUTPUT_FILENAME:_default' \
'--output-filename=[Filename where to output the keys, if not present then write to stdout]:OUTPUT_FILENAME:_default' \
'-t+[Timestamp (as unix timestamp in seconds) for the dates. If unset, use the default 1231006505]:TIMESTAMP:_default' \
'--timestamp=[Timestamp (as unix timestamp in seconds) for the dates. If unset, use the default 1231006505]:TIMESTAMP:_default' \
'-d+[Creation timestamp (as unix timestamp in seconds). If unset, uses the genesis block (1231006505)]:CREATION_TIMESTAMP:_default' \
'--creation-timestamp=[Creation timestamp (as unix timestamp in seconds). If unset, uses the genesis block (1231006505)]:CREATION_TIMESTAMP:_default' \
'-y+[Expiration timestamp (as unix timestamp in seconds). If unset, the keys do not expire]:EXPIRATION_TIMESTAMP:_default' \
'--expiration-timestamp=[Expiration timestamp (as unix timestamp in seconds). If unset, the keys do not expire]:EXPIRATION_TIMESTAMP:_default' \
'-f+[Output format\: SSH or PGP]:FORMAT:(pgp ssh)' \
'--format=[Output format\: SSH or PGP]:FORMAT:(pgp ssh)' \
'-p+[Optional passphrase. If set, -e/--pinentry must not be set. See README.md for details]:PASSPHRASE:_default' \
'--passphrase=[Optional passphrase. If set, -e/--pinentry must not be set. See README.md for details]:PASSPHRASE:_default' \
'-s+[Seed Format\: BIP39, Electrum]:SEED_FORMAT:(bip39 electrum)' \
'--seed-format=[Seed Format\: BIP39, Electrum]:SEED_FORMAT:(bip39 electrum)' \
'-g+[Key derivation algorithm\: xor (legacy default), concat, hkdf (recommended for new keys). Use --algorithm hkdf for new keys. Defaults to xor for backward compatibility]:ALGORITHM:((xor\:"DEPRECATED\: XOR of separate Argon2id hashes of seed and passphrase"
concat\:"DEPRECATED\: Argon2id of concatenated seed and passphrase, split into sign/encrypt keys"
hkdf\:"Argon2id of concatenated seed and passphrase, then HKDF-Expand with domain separation for sign and encrypt keys"))' \
'--algorithm=[Key derivation algorithm\: xor (legacy default), concat, hkdf (recommended for new keys). Use --algorithm hkdf for new keys. Defaults to xor for backward compatibility]:ALGORITHM:((xor\:"DEPRECATED\: XOR of separate Argon2id hashes of seed and passphrase"
concat\:"DEPRECATED\: Argon2id of concatenated seed and passphrase, split into sign/encrypt keys"
hkdf\:"Argon2id of concatenated seed and passphrase, then HKDF-Expand with domain separation for sign and encrypt keys"))' \
'-q+[DEPRECATED! Request seed phrase through an interactive CLI prompt]:INTERACTIVE:(true false)' \
'--interactive=[DEPRECATED! Request seed phrase through an interactive CLI prompt]:INTERACTIVE:(true false)' \
'--output-receipt=[Write an HTML recovery receipt to this file. The receipt records the derivation parameters, key fingerprints, and build provenance — but no secrets — so the key can be regenerated from the mnemonic later]:FILE:_default' \
'(-u --user-id -s --seed-format -g --algorithm -c --use-concatenation -r --use-rfc9106-settings -b --authorization-for-sign-key --auth-subkey -j --just-signkey -f --format -t --timestamp -d --creation-timestamp -y --expiration-timestamp -n --skip-passphrase-for-key-material)--from-receipt=[Regenerate a key from a receipt file (HTML receipt or raw receipt string). The receipt supplies the user ID and all derivation parameters; only the mnemonic (and passphrase, if used) is prompted. The regenerated key'\''s fingerprint is checked against the receipt. Cannot be combined with flags the receipt already supplies]:FILE:_default' \
'-j[Only output the sign key for PGP]' \
'--just-signkey[Only output the sign key for PGP]' \
'-a[Output as armored]' \
'--armor[Output as armored]' \
'-k[Output the public key]' \
'--public-key[Output the public key]' \
'-e[Request passphrase with pinentry. See README.md for details]' \
'--pinentry[Request passphrase with pinentry. See README.md for details]' \
'-c[DEPRECATED\: Use concatenation method. Equivalent to --algorithm concat]' \
'--use-concatenation[DEPRECATED\: Use concatenation method. Equivalent to --algorithm concat]' \
'-r[Use RFC 9106 settings for Argon2id]' \
'--use-rfc9106-settings[Use RFC 9106 settings for Argon2id]' \
'-b[Add authorization capability to the sign key]' \
'--authorization-for-sign-key[Add authorization capability to the sign key]' \
'--auth-subkey[Generate a separate authentication subkey (requires --algorithm hkdf)]' \
'-n[Do not add the passphrase as extra entropy. If set, the passphrase will only be used to encrypt the PGP or SSH key contents, and the key material itself will be generated from the seed and the user id]' \
'--skip-passphrase-for-key-material[Do not add the passphrase as extra entropy. If set, the passphrase will only be used to encrypt the PGP or SSH key contents, and the key material itself will be generated from the seed and the user id]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'-V[Print version]' \
'--version[Print version]' \
&& ret=0
}

(( $+functions[_bip39key_commands] )) ||
_bip39key_commands() {
    local commands; commands=()
    _describe -t commands 'bip39key commands' commands "$@"
}

if [ "$funcstack[1]" = "_bip39key" ]; then
    _bip39key "$@"
else
    compdef _bip39key bip39key
fi
