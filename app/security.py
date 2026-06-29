import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # no I L O U
_ph = PasswordHasher()


def _group(n: int = 5) -> str:
    return "".join(secrets.choice(_CROCKFORD) for _ in range(n))


def generate_key(prefix: str) -> str:
    return f"{prefix}-{_group()}-{_group()}-{_group()}-{_group()}"


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def key_prefix_display(raw_key: str) -> str:
    return raw_key[:12]


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except VerifyMismatchError:
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def _canonical(*fields) -> bytes:
    return "\n".join(str(f) for f in fields).encode("utf-8")


def sign(secret: str, *fields) -> str:
    return hmac.new(secret.encode("utf-8"), _canonical(*fields), hashlib.sha256).hexdigest()


def verify_sig(secret: str, sig: str, *fields) -> bool:
    expected = sign(secret, *fields)
    return hmac.compare_digest(expected.encode(), (sig or "").encode())
