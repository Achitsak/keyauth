from app import security as s


def test_generate_key_format():
    k = s.generate_key("MASTERP")
    parts = k.split("-")
    assert parts[0] == "MASTERP"
    assert len(parts) == 5
    assert all(len(p) == 5 for p in parts[1:])
    assert s.generate_key("MASTERP") != s.generate_key("MASTERP")


def test_hash_key_stable_and_hex():
    h = s.hash_key("MASTERP-AAAAA-BBBBB-CCCCC-DDDDD")
    assert h == s.hash_key("MASTERP-AAAAA-BBBBB-CCCCC-DDDDD")
    assert len(h) == 64


def test_password_roundtrip():
    h = s.hash_password("hunter2")
    assert s.verify_password("hunter2", h)
    assert not s.verify_password("wrong", h)


def test_sign_verify():
    sig = s.sign("secret", "a", "b", 123)
    assert s.verify_sig("secret", sig, "a", "b", 123)
    assert not s.verify_sig("secret", sig, "a", "b", 124)
    assert not s.verify_sig("other", sig, "a", "b", 123)


def test_token_and_nonce_unique():
    assert s.new_token() != s.new_token()
    assert s.new_nonce() != s.new_nonce()
    assert len(s.hash_token("x")) == 64
