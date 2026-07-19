import base64
import hashlib
import hmac
import os

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
LEGACY_PBKDF2_ITERATIONS = 390_000


def _positive_env(name: str, default: int) -> int:
    value = int(os.environ.get(name, str(default)))
    if value <= 0:
        raise RuntimeError(f"{name} harus berupa bilangan bulat positif.")
    return value


PASSWORD_HASHER = PasswordHasher(
    time_cost=_positive_env("ONE_MIND_ARGON2_TIME_COST", 3),
    memory_cost=_positive_env("ONE_MIND_ARGON2_MEMORY_KIB", 65_536),
    parallelism=_positive_env("ONE_MIND_ARGON2_PARALLELISM", 4),
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def _decode_base64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _verify_legacy_pbkdf2(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_text)
        if iterations <= 0 or iterations > 10_000_000:
            return False

        salt = _decode_base64(salt_text)
        expected = _decode_base64(digest_text)
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(candidate, expected)
    except (TypeError, ValueError):
        return False


def verify_and_rehash(password: str, encoded: str) -> tuple[bool, str | None]:
    """Verifikasi password dan kembalikan hash Argon2id pengganti bila perlu."""

    if encoded.startswith("$argon2id$"):
        try:
            PASSWORD_HASHER.verify(encoded, password)
            replacement = (
                hash_password(password)
                if PASSWORD_HASHER.check_needs_rehash(encoded)
                else None
            )
            return True, replacement
        except (InvalidHashError, VerificationError, VerifyMismatchError):
            return False, None

    if encoded.startswith("pbkdf2_sha256$") and _verify_legacy_pbkdf2(
        password,
        encoded,
    ):
        return True, hash_password(password)

    return False, None


def verify_password(password: str, encoded: str) -> bool:
    valid, _ = verify_and_rehash(password, encoded)
    return valid
