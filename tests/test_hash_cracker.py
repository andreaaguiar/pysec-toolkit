import hashlib

import hash_cracker


def test_validate_hash_valid_md5():
    assert hash_cracker.validate_hash("5f4dcc3b5aa765d61d8327deb882cf99", "md5")


def test_validate_hash_wrong_length():
    assert not hash_cracker.validate_hash("abc123", "md5")


def test_validate_hash_non_hex():
    assert not hash_cracker.validate_hash("z" * 32, "md5")


def test_crack_hash_found(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("foo\npassword\nbar\n")
    target = hashlib.md5(b"password").hexdigest()
    assert hash_cracker.crack_hash(str(wordlist), target, "md5") == "password"


def test_crack_hash_not_found(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("foo\nbar\n")
    target = hashlib.md5(b"absent").hexdigest()
    assert hash_cracker.crack_hash(str(wordlist), target, "md5") is None


def test_crack_hash_unsupported_type(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("x\n")
    assert hash_cracker.crack_hash(str(wordlist), "deadbeef", "sha3") is None
