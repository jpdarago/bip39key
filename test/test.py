#!/usr/bin/env python3

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

def change_permissions(filename, permissions):
    if platform.system() != "Windows":
        os.chmod(filename, permissions)

def run_command(cmd, stdinput=None, env={}):
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(os.environ, **env),
    ) as proc:
        try:
            if isinstance(stdinput, str):
                stdinput = str.encode(stdinput)
            stdout, stderr = proc.communicate(input=stdinput, timeout=15)
            if proc.returncode != 0:
                raise Exception(
                    "{} did not finish successfully: \n\n{}".format(
                        cmd, bytes.decode(stderr, "utf-8")
                    )
                )
            return (stdout, stderr)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise Exception("Timeout for {}".format(cmd))


class GPG:
    def __enter__(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        change_permissions(self.tmpdir.name, 0x1C0)
        return self

    def __exit__(self, type, value, traceback):
        shutil.rmtree(self.tmpdir.name)
        self.tmpdir.cleanup()

    def run(self, flags, stdin=None):
        cmd = [
            "gpg",
            "--display-charset",
            "utf-8",
            "-utf8-strings",
            "--homedir",
            self.tmpdir.name,
        ] + flags
        env = {"GNUPGHOME": self.tmpdir.name}
        return run_command(cmd, stdin, env)


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


def run_ssh_keygen(stdin, passphrase=""):
    f = tempfile.NamedTemporaryFile(delete=False)
    try:
        f.write(stdin)
        f.close()
        change_permissions(f.name, 0o700)
        cmd = ["ssh-keygen", "-v", "-y", "-P", passphrase, "-f", f.name]
        return run_command(cmd)
    finally:
        os.unlink(f.name)


def run_bip39key(bip39, userid, flags=[]):
    binary = os.path.join("target", "release", "bip39key")
    cmd = [binary, "-u", userid] + flags
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

ELECTRUM = [
    "work",
    "size",
    "tomato",
    "royal",
    "recipe",
    "old",
    "portion",
    "nut",
    "mask",
    "laptop",
    "diamond",
    "junior",
]

REALNAME = "Satoshi Nakamoto"
EMAIL = "satoshin@gmx.com"
USERID = "{} <{}>".format(REALNAME, EMAIL)
PASS = "m4gicp455w0rd"


def check_binary(binary, message):
    if not shutil.which(binary):
        print("{} is not installed. {}".format(binary, message))
        sys.exit(1)


class Bip39PGPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check_binary("gpg", "Please install GNU Privacy Guard.")
        check_binary("ssh-keygen", "Please install OpenSSH.")
        print("Running cargo...", end="", flush=True)
        run_command(["cargo", "build", "--release"])
        print("Done. Running tests.")

    def check_key(
        self,
        keys,
        fp="A10531F7669DDD0FA50B0A00656C58480711970B",
        subfp="656C58480711970B",
    ):
        self.assertEqual(keys["pub"][7], "ed25519")
        self.assertEqual(keys["fpr"], [fp])
        self.assertEqual(keys["uid"][1], "1231006505")
        self.assertEqual(keys["uid"][3], USERID)
        self.assertEqual(keys["sub"][3], subfp)
        self.assertEqual(keys["sub"][4], "1231006505")
        self.assertEqual(keys["sub"][5], "e")
        self.assertEqual(keys["sub"][6], "cv25519")

    def run_gpg_import(self, gpg, key, filename=None, password=None):
        flags = ["--import"]
        if not filename is None:
            flags.append(filename)
        if not password is None:
            passfile = os.path.join(gpg.tmpdir.name, "passwords.txt")
            with open(passfile, "w") as f:
                f.write(password)
            flags.append("--passphrase-file")
            flags.append(passfile)
            flags.append("--pinentry-mode")
            flags.append("loopback")
            gpg.run(flags, key)
            os.remove(passfile)
        else:
            gpg.run(flags, key)

    def test_gpg_raw(self):
        with GPG() as gpg:
            stdout, _ = run_bip39key(BIP39, USERID)
            self.run_gpg_import(gpg, key=stdout)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.check_key(keys)

    def test_gpg_public(self):
        with GPG() as gpg:
            stdout, _ = run_bip39key(BIP39, USERID, ["--public-key"])
            self.run_gpg_import(gpg, key=stdout)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.assertEqual(keys["pub"][7], "ed25519")
            self.assertEqual(keys["fpr"], ["A10531F7669DDD0FA50B0A00656C58480711970B"])
            self.assertEqual(keys["uid"][3], USERID)

    def test_gpg_raw_with_file(self):
        with GPG() as gpg:
            f = tempfile.NamedTemporaryFile(delete=False)
            stdout, _ = run_bip39key(BIP39, USERID, ["-o", f.name])
            self.run_gpg_import(gpg, filename=f.name, key=stdout)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.check_key(keys)
            os.unlink(f.name)

    def test_gpg_armor(self):
        with GPG() as gpg:
            stdout, _ = run_bip39key(BIP39, USERID, ["-a"])
            self.run_gpg_import(gpg, key=stdout)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.check_key(keys)

    def test_electrum(self):
        with GPG() as gpg:
            stdout, _ = run_bip39key(ELECTRUM, USERID, ["-s", "electrum"])
            self.run_gpg_import(gpg, key=stdout)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.check_key(
                keys,
                fp="384CC65ACAD3BECE74FFF34391BA6BD773B77C9E",
                subfp="91BA6BD773B77C9E",
            )

    def test_ssh(self):
        secretkey, _ = run_bip39key(BIP39, USERID, ["-f", "ssh"])
        keygenpub, _ = run_ssh_keygen(secretkey)
        bip39pub, _ = run_bip39key(BIP39, USERID, ["-f", "ssh", "--public-key"])
        # The bip39 pub might contain less information than ssh-keygen,
        # e.g. it will not contain the comments.
        lhs, rhs = keygenpub.strip(), bip39pub.strip()
        self.assertTrue(lhs.startswith(rhs), msg="{} vs {}".format(lhs, rhs))

    def test_bad_bip39(self):
        with self.assertRaises(Exception):
            run_bip39key(["foobarbaz"], USERID, ["-f", "ssh"])

    def test_bad_bip39_checksum(self):
        mnemonic = BIP39[:]
        mnemonic[-1] = "abandon"
        with self.assertRaises(Exception):
            run_bip39key(mnemonic, USERID, ["-f", "ssh"])

    def test_gpg_import_with_passphrase(self):
        stdout, stderr = run_bip39key(BIP39, USERID, ["-p", PASS])
        with GPG() as gpg:
            passfile = os.path.join(gpg.tmpdir.name, "passwords.txt")
            self.run_gpg_import(gpg, key=stdout, password=PASS)
            keysout, _ = gpg.run(["--with-colons", "--list-keys"])
            keys = parse_gpg_keys(keysout)
            self.check_key(
                keys,
                fp="973FB9F6845B59C12544D62695C556EA825BA259",
                subfp="95C556EA825BA259",
            )
        with GPG() as gpg:
            with self.assertRaises(Exception):
                self.run_gpg_import(gpg, key=stdout, password="badpassword")

    def test_ssh_with_passphrase(self):
        stdout, stderr = run_bip39key(BIP39, USERID, ["-f", "ssh", "-p", PASS])
        run_ssh_keygen(stdout, passphrase=PASS)
        with self.assertRaises(Exception):
            run_ssh_keygen(stdout, passphrase="badpassword")


if __name__ == "__main__":
    unittest.main()
