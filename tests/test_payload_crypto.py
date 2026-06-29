from app import payload_crypto as pc


def test_roundtrip():
    data = b"the real protected script bytes"
    ct, nonce = pc.encrypt_payload(data)
    assert ct != data
    assert pc.decrypt_payload(ct, nonce) == data


def test_unique_nonce_and_ciphertext():
    a_ct, a_n = pc.encrypt_payload(b"x")
    b_ct, b_n = pc.encrypt_payload(b"x")
    assert a_n != b_n and a_ct != b_ct  # random nonce per call


def test_tamper_detected():
    import pytest
    ct, nonce = pc.encrypt_payload(b"secret")
    with pytest.raises(Exception):
        pc.decrypt_payload(ct[:-1] + bytes([ct[-1] ^ 1]), nonce)  # GCM auth fails
