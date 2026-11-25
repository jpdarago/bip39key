#!/usr/bin/env bash
# Build a Debian package around an already-built bip39key binary.
#
#   scripts/build-deb.sh BINARY DEB_ARCH OUTPUT_DIR
#
#   BINARY      path to the bip39key executable to package
#   DEB_ARCH    Debian architecture name: amd64 or arm64
#   OUTPUT_DIR  where to write bip39key_VERSION_ARCH.deb
#
# The release workflow runs this on the static musl binaries, so the package
# has no dependencies and installs on any Debian, Ubuntu or Tails release for
# that architecture. It uses dpkg-deb directly, with no packaging tool between
# the binary and the archive: the release job holds the signing key, and every
# extra tool there is one more thing that has to be trusted.
#
# The version is the upstream version with no Debian revision ("1.10.0", not
# "1.10.0-1"), so an official Debian package of the same release sorts higher
# and replaces this one.
#
# Set SOURCE_DATE_EPOCH for a reproducible archive; it defaults to the time of
# the last commit.
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 BINARY DEB_ARCH OUTPUT_DIR" >&2
    exit 2
fi
binary=$1
arch=$2
out_dir=$3

case "$arch" in
    amd64 | arm64) ;;
    *)
        echo "unsupported Debian architecture: $arch (expected amd64 or arm64)" >&2
        exit 2
        ;;
esac
if [ ! -f "$binary" ]; then
    echo "no such binary: $binary" >&2
    exit 1
fi

repo=$(cd "$(dirname "$0")/.." && pwd)
version=$(grep -m1 '^version' "$repo/Cargo.toml" | sed 's/version = "\(.*\)"/\1/')
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct)}
date_rfc2822=$(date -u -R -d "@$SOURCE_DATE_EPOCH")

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
# mktemp makes the directory 0700; dpkg-deb records that mode for "./".
chmod 755 "$root"

install -D -m 755 "$binary" "$root/usr/bin/bip39key"
install -D -m 644 "$repo/man/bip39key.1" "$root/usr/share/man/man1/bip39key.1"
gzip -9n "$root/usr/share/man/man1/bip39key.1"
install -D -m 644 "$repo/completions/bip39key.bash" \
    "$root/usr/share/bash-completion/completions/bip39key"
install -D -m 644 "$repo/completions/bip39key.zsh" \
    "$root/usr/share/zsh/vendor-completions/_bip39key"

doc="$root/usr/share/doc/bip39key"
install -D -m 644 "$repo/README.md" "$doc/README.md"
{
    echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
    echo "Upstream-Name: bip39key"
    echo "Source: https://github.com/jpdarago/bip39key"
    echo
    echo "Files: *"
    echo "Copyright: 2022 jpdarago"
    echo "License: Expat"
    # The license text, indented as the format requires, with blank lines
    # written as " .". Skips the "MIT License" title and copyright line.
    sed -n '5,$p' "$repo/LICENSE" | sed 's/^$/./; s/^/ /'
} > "$doc/copyright"
chmod 644 "$doc/copyright"
{
    echo "bip39key ($version) unstable; urgency=medium"
    echo
    echo "  * Upstream release $version. See"
    echo "    https://github.com/jpdarago/bip39key/releases/tag/v$version"
    echo
    echo " -- Juan Pablo Darago <jpdarago@gmail.com>  $date_rfc2822"
} > "$doc/changelog"
gzip -9n "$doc/changelog"
chmod 644 "$doc/changelog.gz"

installed_kb=$(du -sk "$root" | cut -f1)
mkdir -m 755 "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<EOF
Package: bip39key
Version: $version
Architecture: $arch
Maintainer: Juan Pablo Darago <jpdarago@gmail.com>
Installed-Size: $installed_kb
Section: utils
Priority: optional
Homepage: https://github.com/jpdarago/bip39key
Suggests: gnupg, openssh-client, age, pinentry-curses | pinentry
Description: deterministic OpenPGP, OpenSSH and age keys from a seed phrase
 bip39key derives OpenPGP (EdDSA/ECDH Curve25519), OpenSSH (Ed25519) and age
 (X25519) keys from a BIP39 or Electrum mnemonic seed phrase, so the same
 phrase always regenerates the same keys.
 .
 This package contains a statically linked binary built by the upstream
 project. It has no dependencies.
EOF
chmod 644 "$root/DEBIAN/control"

# Same timestamps on every run, so the archive is reproducible.
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$out_dir"
deb="$out_dir/bip39key_${version}_${arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$root" "$deb" >/dev/null
echo "$deb"
