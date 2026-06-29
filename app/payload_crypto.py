import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings


def _key() -> bytes:
    return hashlib.sha256(b"keyauth-payload-key:" + settings.server_secret.encode("utf-8")).digest()


def encrypt_payload(plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_payload(ciphertext: bytes, nonce: bytes) -> bytes:
    return AESGCM(_key()).decrypt(nonce, ciphertext, None)
