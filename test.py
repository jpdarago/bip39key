#!/usr/bin/env python3

import os
import subprocess
import tempfile
import unittest


def run_command(cmd, stdinput=None):
    with subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE
    ) as proc:
        try:
            if isinstance(stdinput, str):
                stdinput = str.encode(stdinput)
            stdout, stderr = proc.communicate(input=stdinput, timeout=15)
            if proc.returncode != 0:
                raise Exception(
                    "{} did not finish successfully: {}".format(cmd, stderr)
                )
            return (stdout, stderr)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise Exception("Timeout for {}".format(cmd))


class GPG:
    def __enter__(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        os.chmod(self.tmpdir.name, 0x1C0)
        return self

    def __exit__(self, type, value, traceback):
        self.tmpdir.cleanup()

    def run(self, flags, stdin=None):
        cmd = [
            "gpg",
            "--quiet",
            "--display-charset",
            "utf-8",
            "-utf8-strings",
            "--homedir",
            self.tmpdir.name,
        ] + flags
        return run_command(cmd, stdin)


def parse_gpg_keys(rawstdout):
    stdout = bytes.decode(rawstdout, "utf-8")
    result = {}
    for line in stdout.splitlines():
        head, *tail = line.split(":")
        if head != "tru":
            cols = []
            for part in tail:
                if part:
                    cols.append(part)
            result[head] = cols
    return result


def run_ssh_keygen(stdin):
    f = tempfile.NamedTemporaryFile(delete=False)
    try:
        f.write(stdin)
        f.close()
        cmd = ["ssh-keygen", "-v", "-y", "-P", "", "-f", f.name]
        return run_command(cmd)
    finally:
        os.unlink(f.name)


def run_bip39key(bip39, userid, flags=[]):
    cmd = ["./target/release/bip39key", "-u", userid] + flags
    return run_command(cmd, " ".join(bip39))


BIP39 = [
    "abandon",
    "abandon",
    "abandon",
    "abandon",
    "abandon",
    "abandon",
    "abandon",
    "abandon",
    "abandon",
    "abandon",
    "abandon",
    "about",
]

REALNAME = "Satoshi Nakamoto"
EMAIL = "satoshin@gmx.com"
USERID = "{} <{}>".format(REALNAME, EMAIL)


class Bip39PGPTest(unittest.TestCase):
    def check_key(self, keys, fp="A10531F7669DDD0FA50B0A00656C58480711970B", subfp="656C58480711970B"):
        self.assertEqual(keys["pub"][7], "ed25519")
        self.assertEqual(keys["fpr"], [fp])
        self.assertEqual(keys["uid"][1], "1231006505")
        self.assertEqual(keys["uid"][3], USERID)
        self.assertEqual(keys["sub"][3], subfp)
        self.assertEqual(keys["sub"][4], "1231006505")
        self.assertEqual(keys["sub"][5], "e")
        self.assertEqual(keys["sub"][6], "cv25519")

    def test_gpg_raw(self):
        with GPG() as gpg:
            stdout, stderr = run_bip39key(BIP39, USERID)
            gpg.run(["--import"], stdout)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.check_key(keys)

    def test_gpg_armor(self):
        with GPG() as gpg:
            stdout, stderr = run_bip39key(BIP39, USERID, ["-a"])
            gpg.run(["--import"], stdout)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.check_key(keys)

    def test_ssh(self):
        stdout, stderr = run_bip39key(BIP39, USERID, ["-f", "ssh"])
        run_ssh_keygen(stdout)

    def test_bad_bip39(self):
        with self.assertRaises(Exception):
            run_bip39key(['foobarbaz'], USERID, ["-f", "ssh"])

    def test_bad_bip39_checksum(self):
        mnemonic = BIP39[:]
        mnemonic[-1] = 'abandon'
        with self.assertRaises(Exception):
            run_bip39key(mnemonic, USERID, ["-f", "ssh"])

    def test_gpg_with_passphrase(self):
        with GPG() as gpg:
            stdout, stderr = run_bip39key(BIP39, USERID, ["--passphrase", "m4gicp455w0rd"])
            gpg.run(["--import"], stdout)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.check_key(keys, fp="973FB9F6845B59C12544D62695C556EA825BA259", subfp="95C556EA825BA259")


if __name__ == "__main__":
    unittest.main()
