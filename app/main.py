import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import Depends, FastAPI, Header, HTTPException, Path as ApiPath, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

from app.auth.passwords import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    hash_password,
    verify_and_rehash,
    verify_password,
)
from app.pki.pki import (
    certificate_matches_current_intermediate,
    initialize_pki,
    intermediate_ca_fingerprint,
    issue_certificate,
    remove_user_certificate,
)


APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ONE_MIND_DATA_DIR", APP_DIR / "data"))
DB_PATH = DATA_DIR / "database" / "one_mind.sqlite3"
STORAGE_DIR = DATA_DIR / "storage"
TEMP_UPLOAD_DIR = DATA_DIR / "temp_uploads"
SECRET_PATH = DATA_DIR / "keys" / "server_secret.bin"

SESSION_SECONDS = int(os.environ.get("ONE_MIND_SESSION_SECONDS", "300"))
ADMIN_SESSION_SECONDS = int(os.environ.get("ONE_MIND_ADMIN_SESSION_SECONDS", "300"))
PENDING_LOGIN_SECONDS = int(os.environ.get("ONE_MIND_PENDING_LOGIN_SECONDS", "300"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("ONE_MIND_LOGIN_WINDOW_SECONDS", "600"))
LOGIN_MAX_FAILURES = int(os.environ.get("ONE_MIND_LOGIN_MAX_FAILURES", "8"))
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ONE_MIND_ALLOWED_HOSTS", "*").split(",") if h.strip()]
PKI_AUTO_INIT = os.environ.get("ONE_MIND_PKI_AUTO_INIT", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
FAILED_LOGINS: dict[str, list[float]] = {}
ACCOUNT_STATUSES = ("PENDING", "ACTIVE", "REJECTED", "DELETED")
CERTIFICATE_STATUSES = ("NONE", "ISSUED", "REVOKED", "EXPIRED", "REPLACED")
FILE_STORAGE_FORMAT = "chunked-v1"
DIPP_PROTOCOL = "ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE"
DIPP_PROTOCOL_VERSION = 5
DIPP_PARAMETER_SET = "ER-DIPP-64-16-W8-E2048-R10S12S-Q2500K-v5"
DIPP_ENVELOPE_VERSION = "ONE_MIND-DIPP-EPHEMERAL-R-WEIGHTED-E2048-R10S12S-Q2500K-v5"
DIPP_FILE_PROTOCOL_VERSION = "ONE_MIND_DIPP_EPHEMERAL_R_WEIGHTED_E2048_R10S12S_Q2500K_V5"
DIPP_GEOMETRY_PROFILE = "FIXED-WEISZFELD-24-WEIGHTED-8-R10S12S"
DIPP_KEY_ESTABLISHMENT = "DIPP-ER-WEIGHTED-E2048-R10S12S-Q2500K-v5"
DIPP_KEY_ID_DOMAIN = b"DIPP-ER-WEIGHTED-E2048-R10S12S-Q2500K-KEY-ID-v5"
DIPP_VECTOR_BYTES = 64 * 4
DIPP_COMPONENT_COUNT = 256
DIPP_MODULUS = 65536
DIPP_MAX_COORDINATE_ABS = 34_000_000
DIPP_SESSION_BYTES = 24
USERNAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$"
OPAQUE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$"
MAX_FILE_BYTES = 20 * 1024 * 1024 * 1024
MAX_CHUNK_BYTES = 16 * 1024 * 1024
MAX_TOTAL_CHUNKS = 100_000
MAX_INLINE_UPDATE_BYTES = 128 * 1024 * 1024
MAX_REQUEST_BYTES = 180 * 1024 * 1024
MAX_WRAPPED_KEYS = 256
MAX_AAD_BYTES = 4096
MAX_AUTHORIZATION_HEADER_BYTES = 4096


def reject_control_characters(value: str) -> str:
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise ValueError("Karakter kontrol tidak diperbolehkan.")
    return value


def validate_plain_text(value: str) -> str:
    reject_control_characters(value)
    if "<" in value or ">" in value:
        raise ValueError("Markup HTML tidak diperbolehkan.")
    return value


def validate_filename_value(value: str) -> str:
    reject_control_characters(value)
    if value in {".", ".."} or any(char in value for char in '/\\:*?"<>|'):
        raise ValueError("Nama file mengandung karakter yang tidak diperbolehkan.")
    if value.endswith((" ", ".")):
        raise ValueError("Nama file tidak boleh diakhiri spasi atau titik.")
    stem = value.split(".", 1)[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        raise ValueError("Nama file termasuk nama perangkat yang dilarang.")
    return value


Username = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=3, max_length=80, pattern=USERNAME_PATTERN),
]
OpaqueId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=160, pattern=OPAQUE_ID_PATTERN),
]
DisplayName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=160),
    AfterValidator(validate_plain_text),
]
ShortText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=80),
    AfterValidator(validate_plain_text),
]
ReasonText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, max_length=500),
    AfterValidator(validate_plain_text),
]
FilenameText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=240),
    AfterValidator(validate_filename_value),
]
PathUsername = Annotated[str, ApiPath(min_length=3, max_length=80, pattern=USERNAME_PATTERN)]
PathOpaqueId = Annotated[str, ApiPath(min_length=1, max_length=160, pattern=OPAQUE_ID_PATTERN)]
PathChunkIndex = Annotated[int, ApiPath(ge=0, lt=MAX_TOTAL_CHUNKS)]


class StrictInputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def bearer_token(authorization: str | None, detail: str) -> str:
    if (
        not authorization
        or len(authorization.encode("utf-8")) > MAX_AUTHORIZATION_HEADER_BYTES
        or not authorization.startswith("Bearer ")
    ):
        raise HTTPException(status_code=401, detail=detail)
    token = authorization.removeprefix("Bearer ").strip()
    if not token or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in token):
        raise HTTPException(status_code=401, detail=detail)
    return token


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def cleanup_upload_sessions():

    conn = db()

    rows = conn.execute(
        """
        SELECT
            id,
            expires_at
        FROM upload_sessions;
        """
    ).fetchall()

    now = datetime.now(timezone.utc)

    for row in rows:

        upload_id = row["id"]

        expires_at = datetime.fromisoformat(
            row["expires_at"]
        )

        if expires_at <= now:

            upload_dir = TEMP_UPLOAD_DIR / upload_id

            try:

                if upload_dir.exists():
                    shutil.rmtree(upload_dir)

                conn.execute(
                    "DELETE FROM upload_sessions WHERE id=?",
                    (upload_id,)
                )

            except Exception as e:

                print(
                    f"[Cleanup] Failed to remove upload session {upload_id}: {e}"
                )

    conn.commit()
    conn.close()

def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def max_b64_length(byte_length: int) -> int:
    return ((byte_length + 2) // 3) * 4


def decode_standard_b64(value: str, field: str, *, max_bytes: int, exact_bytes: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) > max_b64_length(max_bytes):
        raise HTTPException(status_code=400, detail=f"Ukuran {field} tidak valid.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=400, detail=f"{field} bukan Base64 valid.") from exc
    if len(decoded) > max_bytes or (exact_bytes is not None and len(decoded) != exact_bytes):
        raise HTTPException(status_code=400, detail=f"Panjang {field} tidak valid.")
    return decoded


def validate_file_envelope(
    value: dict,
    *,
    expected_filename: str,
    expected_version: int,
    allow_ciphertext: bool,
) -> bytes | None:
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="Envelope file harus object.")
    required = {
        "version", "algorithm", "protocol_version", "file_context_id",
        "filename", "mime", "aad_b64", "iv_b64",
    }
    optional = {"file_id"}
    if allow_ciphertext:
        required.add("ciphertext_b64")
    if not required.issubset(value) or set(value) - required - optional:
        raise HTTPException(status_code=400, detail="Schema envelope file tidak canonical.")
    if (
        not isinstance(value["version"], int)
        or isinstance(value["version"], bool)
        or value["version"] != expected_version
    ):
        raise HTTPException(status_code=400, detail="Versi envelope file tidak valid.")
    if value["algorithm"] != "AES-256-GCM" or value["protocol_version"] != DIPP_FILE_PROTOCOL_VERSION:
        raise HTTPException(status_code=400, detail="Algoritme atau protocol envelope file tidak dikenal.")
    try:
        filename = validate_filename_value(str(value["filename"]).strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if filename != expected_filename:
        raise HTTPException(status_code=400, detail="Nama file pada envelope tidak cocok.")
    mime = value["mime"]
    if (
        not isinstance(mime, str)
        or not 1 <= len(mime) <= 160
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,79}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,79}", mime)
    ):
        raise HTTPException(status_code=400, detail="MIME type tidak valid.")
    try:
        reject_control_characters(mime)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    validate_dipp_b64url(value["file_context_id"], 24, "file_context_id")
    aad = decode_standard_b64(value["aad_b64"], "aad_b64", max_bytes=MAX_AAD_BYTES)
    try:
        aad_value = json.loads(aad.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="AAD file tidak valid.") from exc
    if aad_value != {"filename": filename, "type": mime}:
        raise HTTPException(status_code=400, detail="AAD file tidak cocok dengan metadata envelope.")
    decode_standard_b64(value["iv_b64"], "iv_b64", max_bytes=12, exact_bytes=12)
    if "file_id" in value and (
        not isinstance(value["file_id"], str)
        or len(value["file_id"]) > 160
        or not re.fullmatch(OPAQUE_ID_PATTERN, value["file_id"])
    ):
        raise HTTPException(status_code=400, detail="file_id envelope tidak valid.")
    if allow_ciphertext:
        return decode_standard_b64(
            value["ciphertext_b64"],
            "ciphertext_b64",
            max_bytes=MAX_INLINE_UPDATE_BYTES,
        )
    return None


def validate_dipp_b64url(value: str, expected_length: int, field: str) -> None:
    if not isinstance(value, str) or not value or any(
        char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for char in value
    ):
        raise HTTPException(status_code=400, detail=f"{field} bukan Base64url canonical.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=400, detail=f"{field} bukan Base64url valid.") from exc
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != expected_length or canonical != value:
        raise HTTPException(status_code=400, detail=f"Panjang atau encoding {field} tidak valid.")


def validate_dipp_vector(value: str) -> None:
    validate_dipp_b64url(value, DIPP_VECTOR_BYTES, "vector")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    for offset in range(0, len(raw), 4):
        coordinate = int.from_bytes(raw[offset:offset + 4], "big", signed=True)
        if abs(coordinate) > DIPP_MAX_COORDINATE_ABS:
            raise HTTPException(
                status_code=400,
                detail="Coordinate Ephemeral-R berada di luar domain profile.",
            )


def dipp_transcript(value: dict) -> dict:
    return {
        key: value[key]
        for key in (
            "version",
            "parameter_profile",
            "sender_id",
            "recipient_id",
            "recipient_key_id",
            "public_seed",
            "B_b",
            "session_id",
            "file_context_id",
            "dipp_components",
            "algorithms",
        )
    }


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_dipp_wrapped_key(value: dict) -> None:
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="Wrapped key DIPP harus object.")
    if "V" in value or "n_bits" in value or str(value.get("algorithm", "")).startswith("DIPP-KEM"):
        raise HTTPException(status_code=400, detail="Wrapped key DIPP legacy ditolak.")
    required = {
        "version",
        "parameter_profile",
        "sender_id",
        "recipient_id",
        "recipient_key_id",
        "public_seed",
        "B_b",
        "session_id",
        "file_context_id",
        "dipp_components",
        "algorithms",
        "transcript_hash",
        "key_establishment_algorithm",
        "wrap_algorithm",
        "wrap_nonce",
        "wrapped_file_key",
        "sender_signature_algorithm",
        "sender_signature",
    }
    if set(value) != required:
        raise HTTPException(status_code=400, detail="Schema wrapped key Ephemeral-R tidak canonical.")
    if value["version"] != DIPP_ENVELOPE_VERSION or value["parameter_profile"] != DIPP_PARAMETER_SET:
        raise HTTPException(status_code=400, detail="Protocol wrapped key DIPP tidak dikenal.")
    if (
        value["key_establishment_algorithm"] != DIPP_KEY_ESTABLISHMENT
        or value["wrap_algorithm"] != "AES-256-GCM"
        or value["sender_signature_algorithm"] != "RSA-PKCS1-v1_5-SHA512"
    ):
        raise HTTPException(status_code=400, detail="Algoritme pembungkus key tidak dikenal.")
    if value["algorithms"] != {
        "geometry": DIPP_GEOMETRY_PROFILE,
        "extractor": "HKDF-SHA-256",
        "key_establishment": DIPP_KEY_ESTABLISHMENT,
    }:
        raise HTTPException(status_code=400, detail="Suite algoritme Ephemeral-R tidak canonical.")
    validate_dipp_b64url(value["session_id"], DIPP_SESSION_BYTES, "session_id")
    validate_dipp_b64url(value["file_context_id"], 24, "file_context_id")
    for field in ("sender_id", "recipient_id"):
        if (
            not isinstance(value[field], str)
            or not re.fullmatch(USERNAME_PATTERN, value[field])
        ):
            raise HTTPException(status_code=400, detail=f"Field {field} tidak valid.")
    if not isinstance(value["recipient_key_id"], str) or not secrets.compare_digest(
        value["recipient_key_id"], value["recipient_key_id"].lower()
    ) or len(value["recipient_key_id"]) != 64:
        raise HTTPException(status_code=400, detail="recipient_key_id tidak valid.")
    try:
        bytes.fromhex(value["recipient_key_id"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="recipient_key_id tidak valid.") from exc
    validate_dipp_b64url(value["public_seed"], 32, "public_seed")
    validate_dipp_vector(value["B_b"])
    components = value["dipp_components"]
    if not isinstance(components, list) or len(components) != DIPP_COMPONENT_COUNT:
        raise HTTPException(status_code=400, detail="Ephemeral-R wajib memiliki 256 komponen.")
    seen: set[tuple[str, int]] = set()
    for component in components:
        if not isinstance(component, dict) or set(component) != {"U", "V"}:
            raise HTTPException(status_code=400, detail="Komponen Ephemeral-R tidak canonical.")
        validate_dipp_vector(component["U"])
        if not isinstance(component["V"], int) or isinstance(component["V"], bool) or not 0 <= component["V"] < DIPP_MODULUS:
            raise HTTPException(status_code=400, detail="V_i Ephemeral-R berada di luar Z_q.")
        fingerprint = (component["U"], component["V"])
        if fingerprint in seen:
            raise HTTPException(status_code=400, detail="Komponen Ephemeral-R duplikat.")
        seen.add(fingerprint)
    validate_dipp_b64url(value["transcript_hash"], 32, "transcript_hash")
    validate_dipp_b64url(value["wrap_nonce"], 12, "wrap_nonce")
    validate_dipp_b64url(value["wrapped_file_key"], 48, "wrapped_file_key")
    validate_dipp_b64url(value["sender_signature"], 512, "sender_signature")
    expected_hash = hashlib.sha256(canonical_json(dipp_transcript(value))).digest()
    actual_hash = base64.urlsafe_b64decode(value["transcript_hash"] + "=" * (-len(value["transcript_hash"]) % 4))
    if not secrets.compare_digest(expected_hash, actual_hash):
        raise HTTPException(status_code=400, detail="Hash transcript Ephemeral-R tidak cocok.")


def validate_dipp_public_identity(value: dict, username: str) -> None:
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="Public identity DIPP harus object.")
    required = {
        "protocol", "version", "type", "user_id", "key_id",
        "parameter_profile", "public_seed", "B_b",
    }
    if set(value) != required:
        raise HTTPException(status_code=400, detail="Schema public identity DIPP tidak canonical.")
    if "V" in value or "n_bits" in value or str(value.get("algorithm", "")).startswith("DIPP-KEM"):
        raise HTTPException(status_code=400, detail="Public identity DIPP legacy ditolak.")
    if (
        value.get("protocol") != DIPP_PROTOCOL
        or value.get("version") != DIPP_PROTOCOL_VERSION
        or value.get("type") != "ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE_PUBLIC"
        or value.get("user_id") != username
        or value.get("parameter_profile") != DIPP_PARAMETER_SET
    ):
        raise HTTPException(status_code=400, detail="Public identity Ephemeral-R DIPP standalone tidak valid.")
    validate_dipp_b64url(value.get("public_seed"), 32, "public_seed")
    validate_dipp_vector(value.get("B_b"))
    key_id = value.get("key_id")
    if not isinstance(key_id, str) or len(key_id) != 64:
        raise HTTPException(status_code=400, detail="key_id Ephemeral-R tidak valid.")
    try:
        bytes.fromhex(key_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="key_id Ephemeral-R tidak valid.") from exc
    expected_key_id = hashlib.sha256(
        DIPP_KEY_ID_DOMAIN
        + username.encode("utf-8")
        + base64.urlsafe_b64decode(value["public_seed"] + "=" * (-len(value["public_seed"]) % 4))
        + base64.urlsafe_b64decode(value["B_b"] + "=" * (-len(value["B_b"]) % 4))
    ).hexdigest()
    if not secrets.compare_digest(expected_key_id, key_id):
        raise HTTPException(status_code=400, detail="key_id Ephemeral-R tidak cocok dengan public material.")


def validate_pki_public_key(value: str) -> None:
    try:
        public_key = serialization.load_pem_public_key(value.encode("ascii"))
    except (AttributeError, UnicodeError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="RSA public key registrasi tidak valid.") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise HTTPException(status_code=400, detail="Login public key wajib RSA.")
    numbers = public_key.public_numbers()
    if public_key.key_size != 4096 or numbers.e != 65537:
        raise HTTPException(status_code=400, detail="RSA login key wajib 4096-bit dengan exponent 65537.")


def register_dipp_ciphertext(conn: sqlite3.Connection, value: dict, sender: str, recipient: str) -> None:
    validate_dipp_wrapped_key(value)
    if value["sender_id"] != sender or value["recipient_id"] != recipient:
        raise HTTPException(status_code=400, detail="Binding sender/recipient Ephemeral-R tidak cocok.")
    rows = conn.execute(
        "SELECT username, public_key, pki_public_key, account_status FROM users WHERE username IN (?, ?)",
        (sender, recipient),
    ).fetchall()
    users_by_name = {row["username"]: row for row in rows}
    if sender not in users_by_name or recipient not in users_by_name:
        raise HTTPException(status_code=404, detail="Identitas Ephemeral-R tidak ditemukan.")
    if any(users_by_name[name]["account_status"] != "ACTIVE" for name in {sender, recipient}):
        raise HTTPException(status_code=403, detail="Akun Ephemeral-R tidak aktif.")
    recipient_public = json.loads(users_by_name[recipient]["public_key"])
    validate_dipp_public_identity(recipient_public, recipient)
    for field, public_field in (("recipient_key_id", "key_id"), ("public_seed", "public_seed"), ("B_b", "B_b")):
        if not secrets.compare_digest(value[field], recipient_public[public_field]):
            raise HTTPException(status_code=400, detail="Public material penerima pada transcript tidak cocok.")
    try:
        signing_key = serialization.load_pem_public_key(users_by_name[sender]["pki_public_key"].encode("ascii"))
        signature = base64.urlsafe_b64decode(value["sender_signature"] + "=" * (-len(value["sender_signature"]) % 4))
        transcript_hash = base64.urlsafe_b64decode(value["transcript_hash"] + "=" * (-len(value["transcript_hash"]) % 4))
        signing_key.verify(signature, transcript_hash, padding.PKCS1v15(), hashes.SHA512())
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Public signing key pengirim tidak valid.") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Signature transcript Ephemeral-R tidak valid.") from exc
    try:
        conn.execute(
            """
            INSERT INTO dipp_ciphertexts (
                session_id, sender_id, recipient_id, recipient_key_id,
                transcript_hash, file_context_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                value["session_id"], sender, recipient, value["recipient_key_id"],
                value["transcript_hash"], value["file_context_id"], now_iso(),
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Session/transcript Ephemeral-R sudah pernah digunakan.") from exc


def new_id(n: int = 16) -> str:
    return secrets.token_hex(n // 2)

def file_storage_dir(file_id: str, create_parent: bool = True) -> Path:
    shard = file_id[:2].lower()
    shard_dir = STORAGE_DIR / shard

    if create_parent:
        shard_dir.mkdir(parents=True, exist_ok=True)

    return shard_dir / file_id


def envelope_path(file_id: str, create_dir: bool = True) -> Path:
    folder = file_storage_dir(file_id, create_parent=create_dir)
    if create_dir:
        folder.mkdir(parents=True, exist_ok=True)
    return folder / "envelope.json"


def stored_file_context(file_id: str) -> str:
    path = envelope_path(file_id, create_dir=False)
    try:
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            raise ValueError("Envelope file tidak tersedia atau terlalu besar.")
        value = json.loads(path.read_text(encoding="utf-8"))
        context = value.get("file_context_id")
        validate_dipp_b64url(context, 24, "file_context_id")
        return context
    except HTTPException:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Metadata envelope file tidak valid.") from exc


def ciphertext_chunk_path(file_id: str, chunk_index: int) -> Path:
    return file_storage_dir(file_id, create_parent=False) / f"chunk_{chunk_index:06d}.bin"


def get_secret() -> bytes:
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(secrets.token_bytes(32))
        SECRET_PATH.chmod(0o600)
    value = SECRET_PATH.read_bytes()
    if len(value) < 32:
        raise RuntimeError("Server signing secret tidak valid atau terlalu pendek.")
    return value


def sign_token(username: str) -> str:
    nonce = new_id(24)
    payload = {
        "type": "user",
        "username": username,
        "nonce": nonce,
        "idle": SESSION_SECONDS,
        "exp": int(time.time()) + SESSION_SECONDS,
    }
    raw = b64e(json.dumps(payload, sort_keys=True).encode("utf-8"))
    sig = hmac.new(get_secret(), raw.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def sign_pending_login_token(username: str) -> str:
    nonce = new_id(24)
    payload = {
        "type": "login_pending",
        "username": username,
        "nonce": nonce,
        "exp": int(time.time()) + PENDING_LOGIN_SECONDS,
    }
    raw = b64e(json.dumps(payload, sort_keys=True).encode("utf-8"))
    sig = hmac.new(get_secret(), raw.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def verify_pending_login_token(token: str) -> str:
    try:
        raw, sig = token.split(".", 1)
        expected = hmac.new(get_secret(), raw.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError
        payload = json.loads(b64d(raw).decode("utf-8"))
        if payload.get("type") != "login_pending":
            raise ValueError
        if int(payload.get("exp", 0)) < int(time.time()):
            raise HTTPException(
                status_code=401,
                detail="Proses login sudah kedaluwarsa. Silakan login ulang.",
            )
        return payload["username"]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail="Token proses login tidak valid.",
        ) from exc


def verify_token(token: str) -> str:
    try:
        raw, sig = token.split(".", 1)
        expected = hmac.new(get_secret(), raw.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError
        payload = json.loads(b64d(raw).decode("utf-8"))
        if payload.get("type") != "user":
            raise ValueError
        if int(payload.get("exp", 0)) < int(time.time()):
            raise HTTPException(status_code=401, detail="Sesi sudah kedaluwarsa. Silakan login ulang.")
        return payload["username"]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Token sesi tidak valid.") from exc


def sign_admin_token(username: str) -> str:
    nonce = new_id(24)
    payload = {
        "type": "admin",
        "username": username,
        "nonce": nonce,
        "idle": ADMIN_SESSION_SECONDS,
        "exp": int(time.time()) + ADMIN_SESSION_SECONDS,
    }
    raw = b64e(json.dumps(payload, sort_keys=True).encode("utf-8"))
    sig = hmac.new(get_secret(), raw.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def verify_admin_token(token: str) -> str:
    try:
        raw, sig = token.split(".", 1)
        expected = hmac.new(get_secret(), raw.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError
        payload = json.loads(b64d(raw).decode("utf-8"))
        if payload.get("type") != "admin":
            raise ValueError
        if int(payload.get("exp", 0)) < int(time.time()):
            raise HTTPException(status_code=401, detail="Sesi admin sudah kedaluwarsa. Silakan login ulang.")
        return payload["username"]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Token admin tidak valid.") from exc


def login_bucket(request: Request, username: str) -> str:
    client = request.client.host if request.client else "unknown"
    return f"{client}:{username.lower()}"


def check_login_rate(request: Request, username: str) -> str:
    key = login_bucket(request, username)
    now = time.time()
    recent = [ts for ts in FAILED_LOGINS.get(key, []) if now - ts < LOGIN_WINDOW_SECONDS]
    FAILED_LOGINS[key] = recent
    if len(recent) >= LOGIN_MAX_FAILURES:
        raise HTTPException(status_code=429, detail="Terlalu banyak percobaan login gagal. Tunggu beberapa menit.")
    return key


def record_login_failure(key: str) -> None:
    FAILED_LOGINS.setdefault(key, []).append(time.time())


def clear_login_failures(key: str) -> None:
    FAILED_LOGINS.pop(key, None)

def verify_pki_signature(
    public_key_pem: str,
    nonce: str,
    signature_b64: str,
) -> bool:

    try:

        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )

        signature = base64.b64decode(
            signature_b64,
            validate=True
        )

        public_key.verify(
            signature,
            nonce.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA512(),
        )

        return True

    except Exception:
        return False


def file_permission(conn: sqlite3.Connection, file_id: str, username: str) -> str | None:
    file_row = conn.execute("SELECT owner FROM files WHERE id=?", (file_id,)).fetchone()
    if not file_row:
        return None
    if file_row["owner"] == username:
        return "owner"
    share_row = conn.execute(
        "SELECT permission FROM shares WHERE file_id=? AND recipient=?",
        (file_id, username),
    ).fetchone()
    return share_row["permission"] if share_row else None


def require_file_permission(
    conn: sqlite3.Connection,
    file_id: str,
    username: str,
    allowed: set[str],
) -> str:
    permission = file_permission(conn, file_id, username)
    if permission is None:
        raise HTTPException(status_code=404, detail="File tidak ditemukan atau tidak bisa diakses.")
    if permission not in allowed:
        raise HTTPException(status_code=403, detail="Hak akses tidak cukup.")
    return permission


def access_usernames(conn: sqlite3.Connection, file_id: str) -> set[str]:
    rows = conn.execute("SELECT recipient FROM shares WHERE file_id=?", (file_id,)).fetchall()
    return {row["recipient"] for row in rows}


def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,

            display_name TEXT NOT NULL,

            password_hash TEXT NOT NULL,

            nip TEXT NOT NULL,

            rank TEXT NOT NULL,

            position TEXT NOT NULL,

            public_key TEXT NOT NULL,

            pki_public_key TEXT,

            account_status TEXT NOT NULL DEFAULT 'PENDING',

            certificate_status TEXT NOT NULL DEFAULT 'NONE',

            created_at TEXT NOT NULL,

            approved_at TEXT,
            approved_by TEXT,

            revoked_at TEXT,
            revoked_by TEXT,

            deleted_at TEXT,
            deleted_by TEXT
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            filename TEXT NOT NULL,
            envelope_name TEXT NOT NULL,
            encrypted_size INTEGER NOT NULL,
            is_hidden INTEGER NOT NULL DEFAULT 1,
            storage_format TEXT NOT NULL DEFAULT 'chunked-v1',
            chunk_size INTEGER NOT NULL DEFAULT 0,
            total_chunks INTEGER NOT NULL DEFAULT 0,
            ciphertext_size INTEGER NOT NULL DEFAULT 0,
            ciphertext_sha256 TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(owner) REFERENCES users(username)
        );

        CREATE TABLE IF NOT EXISTS shares (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            owner TEXT NOT NULL,
            recipient TEXT NOT NULL,
            wrapped_key TEXT NOT NULL,
            permission TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT NOT NULL,
            FOREIGN KEY(file_id) REFERENCES files(id),
            FOREIGN KEY(owner) REFERENCES users(username),
            FOREIGN KEY(recipient) REFERENCES users(username)
        );

        CREATE TABLE IF NOT EXISTS file_requests (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            owner TEXT NOT NULL,
            requester TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            requested_at TEXT NOT NULL,
            resolved_at TEXT,
            FOREIGN KEY(file_id) REFERENCES files(id),
            FOREIGN KEY(owner) REFERENCES users(username),
            FOREIGN KEY(requester) REFERENCES users(username)
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_file_requests_pending
        ON file_requests(file_id, requester)
        WHERE status='PENDING';

        CREATE INDEX IF NOT EXISTS idx_file_requests_owner_status
        ON file_requests(owner, status, requested_at);

        CREATE TABLE IF NOT EXISTS certificate_requests (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            csr_pem TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            requested_at TEXT NOT NULL,
            approved_at TEXT,
            approved_by TEXT,
            FOREIGN KEY(username) REFERENCES users(username)
        );

        CREATE TABLE IF NOT EXISTS certificate_challenges (
            username TEXT PRIMARY KEY,
            nonce TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
        );

        CREATE TABLE IF NOT EXISTS certificates (
            serial_number TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            certificate_pem TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
        );

        CREATE TABLE IF NOT EXISTS certificate_revocation (
            serial_number TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL,
            revoked_by TEXT NOT NULL,
            reason TEXT
        );

        CREATE TABLE IF NOT EXISTS administrators (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS admin_audit_log (
            id TEXT PRIMARY KEY,
            admin_username TEXT NOT NULL,
            action TEXT NOT NULL,
            target_username TEXT,
            detail TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS system_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        DROP TABLE IF EXISTS dipp_sessions;

        CREATE TABLE IF NOT EXISTS dipp_ciphertexts (
            session_id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            recipient_key_id TEXT NOT NULL,
            transcript_hash TEXT NOT NULL UNIQUE,
            file_context_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(username),
            FOREIGN KEY(recipient_id) REFERENCES users(username)
        );

        CREATE INDEX IF NOT EXISTS idx_dipp_ciphertexts_recipient
        ON dipp_ciphertexts(recipient_id, created_at);
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS upload_sessions (
            id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            chunk_size INTEGER NOT NULL,
            total_chunks INTEGER NOT NULL,
            uploaded_chunks INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        """
    )

    # ==========================================================
    # SHARES MIGRATION
    # ==========================================================

    share_columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(shares)"
        ).fetchall()
    }

    if "permission" not in share_columns:
        conn.execute(
            "ALTER TABLE shares ADD COLUMN permission TEXT NOT NULL DEFAULT 'viewer'"
        )
        conn.execute(
            "UPDATE shares SET permission='owner' WHERE recipient=owner"
        )

    # File lama tetap privat sampai pemilik memilih menampilkannya di katalog.
    file_columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(files)"
        ).fetchall()
    }

    if "is_hidden" not in file_columns:
        conn.execute(
            "ALTER TABLE files ADD COLUMN is_hidden INTEGER NOT NULL DEFAULT 1"
        )

    if "storage_format" not in file_columns:
        conn.execute(
            "ALTER TABLE files ADD COLUMN storage_format TEXT NOT NULL DEFAULT 'chunked-v1'"
        )
    if "chunk_size" not in file_columns:
        conn.execute(
            "ALTER TABLE files ADD COLUMN chunk_size INTEGER NOT NULL DEFAULT 0"
        )
    if "total_chunks" not in file_columns:
        conn.execute(
            "ALTER TABLE files ADD COLUMN total_chunks INTEGER NOT NULL DEFAULT 0"
        )
    if "ciphertext_size" not in file_columns:
        conn.execute(
            "ALTER TABLE files ADD COLUMN ciphertext_size INTEGER NOT NULL DEFAULT 0"
        )
    if "ciphertext_sha256" not in file_columns:
        conn.execute(
            "ALTER TABLE files ADD COLUMN ciphertext_sha256 TEXT NOT NULL DEFAULT ''"
        )

    # ==========================================================
    # USERS MIGRATION
    # ==========================================================

    user_columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    }

    if "nip" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN nip TEXT NOT NULL DEFAULT ''")
    if "rank" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN rank TEXT NOT NULL DEFAULT ''")
    if "position" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN position TEXT NOT NULL DEFAULT ''")
    if "pki_public_key" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN pki_public_key TEXT")
    if "account_status" not in user_columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN account_status TEXT NOT NULL DEFAULT 'PENDING'"
        )
    if "certificate_status" not in user_columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN certificate_status TEXT NOT NULL DEFAULT 'NONE'"
        )
    if "approved_at" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN approved_at TEXT")
    if "approved_by" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN approved_by TEXT")
    if "revoked_at" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN revoked_at TEXT")
    if "revoked_by" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN revoked_by TEXT")
    if "deleted_at" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN deleted_at TEXT")
    if "deleted_by" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN deleted_by TEXT")

    conn.commit()

    return conn


def reconcile_certificates_after_ca_rotation(conn: sqlite3.Connection) -> int:
    """Ganti status certificate yang tidak diterbitkan Intermediate CA aktif."""

    fingerprint = intermediate_ca_fingerprint()
    active_certificates = conn.execute(
        """
        SELECT serial_number, username, certificate_pem
        FROM certificates
        WHERE status='ACTIVE'
        """
    ).fetchall()

    affected_users: set[str] = set()

    for certificate in active_certificates:
        if certificate_matches_current_intermediate(certificate["certificate_pem"]):
            continue

        conn.execute(
            "UPDATE certificates SET status='REPLACED' WHERE serial_number=?",
            (certificate["serial_number"],),
        )
        affected_users.add(certificate["username"])

    for username in affected_users:
        remaining = conn.execute(
            """
            SELECT 1
            FROM certificates
            WHERE username=? AND status='ACTIVE'
            LIMIT 1
            """,
            (username,),
        ).fetchone()

        if not remaining:
            conn.execute(
                "UPDATE users SET certificate_status='NONE' WHERE username=?",
                (username,),
            )
            remove_user_certificate(username)

    conn.execute(
        """
        INSERT INTO system_metadata (key, value, updated_at)
        VALUES ('pki_intermediate_fingerprint', ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value=excluded.value,
            updated_at=excluded.updated_at
        """,
        (fingerprint, now_iso()),
    )

    return len(affected_users)

def current_pending_login_user(
    authorization: str | None = Header(default=None),
) -> str:
    username = verify_pending_login_token(
        bearer_token(authorization, "Token proses login diperlukan.")
    )

    conn = db()
    row = conn.execute(
        "SELECT account_status FROM users WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Akun tidak ditemukan.")

    enforce_active_account(row["account_status"])
    return username


def current_user(authorization: str | None = Header(default=None)) -> str:
    username = verify_token(bearer_token(authorization, "Login diperlukan."))

    conn = db()
    row = conn.execute(
        """
        SELECT account_status
        FROM users
        WHERE username=?
        """,
        (
            username,
        ),
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Akun tidak ditemukan.")
        

    enforce_active_account(row["account_status"])

    return username


def account_status_detail(account_status: str) -> str:
    if account_status == "PENDING":
        return "Akun sedang menunggu approval administrator."
    if account_status == "REJECTED":
        return "Akun sudah ditolak atau dicabut oleh administrator."
    if account_status == "DELETED":
        return "Akun sudah dihapus oleh administrator."
    return "Status akun tidak aktif."


def enforce_active_account(account_status: str) -> None:
    if account_status != "ACTIVE":
        raise HTTPException(
            status_code=403,
            detail=account_status_detail(account_status),
        )


def current_admin(authorization: str | None = Header(default=None)) -> str:
    admin_username = verify_admin_token(
        bearer_token(authorization, "Login admin diperlukan.")
    )

    conn = db()
    exists = conn.execute(
        """
        SELECT 1
        FROM administrators
        WHERE username=?
        """,
        (
            admin_username,
        ),
    ).fetchone()
    conn.close()

    if not exists:
        raise HTTPException(status_code=401, detail="Session admin tidak lagi valid.")

    return admin_username


def admin_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) AS total FROM administrators").fetchone()
    return int(row["total"])


def user_admin_view(row: sqlite3.Row) -> dict:
    return {
        "username": row["username"],
        "display_name": row["display_name"],
        "nip": row["nip"],
        "rank": row["rank"],
        "position": row["position"],
        "account_status": row["account_status"],
        "certificate_status": row["certificate_status"],
        "created_at": row["created_at"],
        "approved_at": row["approved_at"],
        "approved_by": row["approved_by"],
        "revoked_at": row["revoked_at"],
        "revoked_by": row["revoked_by"],
        "deleted_at": row["deleted_at"],
        "deleted_by": row["deleted_by"],
        "has_dipp_public_key": bool(row["public_key"]),
        "has_pki_public_key": bool(row["pki_public_key"]),
    }


def record_admin_audit(
    conn: sqlite3.Connection,
    admin_username: str,
    action: str,
    target_username: str | None = None,
    detail: dict | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO admin_audit_log
        (
            id,
            admin_username,
            action,
            target_username,
            detail,
            created_at
        )
        VALUES
        (?, ?, ?, ?, ?, ?)
        """,
        (
            new_id(),
            admin_username,
            action,
            target_username,
            json.dumps(detail or {}, ensure_ascii=False, separators=(",", ":")),
            now_iso(),
        ),
    )


class RegisterIn(StrictInputModel):

    username: Username
    display_name: DisplayName
    password: str = Field(
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
    )
    # Identitas Personel
    nip: ShortText
    rank: ShortText
    position: DisplayName
    # DIPP
    public_key: dict = Field(max_length=8)
    # PKI
    pki_public_key: str = Field(min_length=256, max_length=10_000)


class LoginIn(StrictInputModel):
    username: Username
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class LoginVerifyIn(StrictInputModel):
    nonce: str = Field(min_length=16, max_length=160, pattern=OPAQUE_ID_PATTERN)
    signature: str = Field(min_length=256, max_length=1024)
    public_key_pem: str = Field(min_length=256, max_length=10_000)


class AdminSetupIn(StrictInputModel):
    username: Username
    password: str = Field(
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
    )


class AdminLoginIn(StrictInputModel):
    username: Username
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class AdminPasswordChangeIn(StrictInputModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
    )


class AdminUserEditIn(StrictInputModel):
    display_name: DisplayName
    nip: ShortText
    rank: ShortText
    position: DisplayName


class AdminUserReasonIn(StrictInputModel):
    reason: ReasonText | None = None


class FileUploadIn(StrictInputModel):
    filename: FilenameText
    envelope: dict
    wrapped_key_for_owner: dict

class CertificateChallengeOut(BaseModel):
    nonce: str


class ShareIn(StrictInputModel):
    file_id: OpaqueId
    recipient: Username
    wrapped_key: dict
    permission: Literal["viewer", "editor"] = "viewer"


class UploadStartIn(StrictInputModel):
    filename: FilenameText
    file_size: int = Field(gt=0, le=MAX_FILE_BYTES)
    chunk_size: int = Field(gt=0, le=MAX_CHUNK_BYTES)
    total_chunks: int = Field(gt=0, le=MAX_TOTAL_CHUNKS)


class UploadChunkIn(StrictInputModel):
    upload_id: OpaqueId
    chunk_index: int = Field(ge=0, lt=MAX_TOTAL_CHUNKS)
    total_chunks: int = Field(gt=0, le=MAX_TOTAL_CHUNKS)
    data_b64: str = Field(min_length=4, max_length=max_b64_length(MAX_CHUNK_BYTES))


class UploadFinishIn(StrictInputModel):
    upload_id: OpaqueId
    envelope: dict
    wrapped_key_for_owner: dict
    ciphertext_sha256: str = Field(min_length=44, max_length=44)
    is_hidden: bool = True


class WrappedKeyIn(StrictInputModel):
    recipient: Username
    wrapped_key: dict


class FileUpdateIn(StrictInputModel):
    filename: FilenameText
    envelope: dict
    wrapped_keys: list[WrappedKeyIn] = Field(min_length=1, max_length=MAX_WRAPPED_KEYS)


class FileRenameIn(StrictInputModel):
    filename: FilenameText


class FileVisibilityIn(StrictInputModel):
    is_hidden: bool


class FileRequestApprovalIn(StrictInputModel):
    wrapped_key: dict


app = FastAPI(title="ONE_MIND DIPP Ephemeral-R", version="4.0-dipp-ephemeral-r")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.query_params:
        return JSONResponse(
            status_code=400,
            content={"detail": "Query parameter tidak didukung pada endpoint ini."},
        )
    if request.url.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH"}:
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return JSONResponse(status_code=415, content={"detail": "Content-Type wajib application/json."})
        raw_length = request.headers.get("content-length")
        if raw_length is None:
            return JSONResponse(status_code=411, content={"detail": "Content-Length wajib dikirim."})
        try:
            content_length = int(raw_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Content-Length tidak valid."})
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            return JSONResponse(status_code=413, content={"detail": "Request body terlalu besar."})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'wasm-unsafe-eval'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path == "/" or request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.on_event("startup")
def startup():
    initialize_pki(auto_init=PKI_AUTO_INIT)
    get_secret()
    conn = db()
    replaced = reconcile_certificates_after_ca_rotation(conn)
    conn.commit()
    conn.close()
    if replaced:
        print(f"[PKI] {replaced} akun memerlukan penerbitan ulang certificate.")


@app.get("/health")
def health():
    return {
        "ok": True,
        "transport": "HTTPS/TLS when run via docker entrypoint",
        "crypto_profile": DIPP_FILE_PROTOCOL_VERSION,
        "server_knowledge": "public-transcript-and-ciphertext-only",
    }


@app.get("/api/admin/setup-status")
def admin_setup_status():
    conn = db()
    total = admin_count(conn)
    conn.close()
    return {"setup_required": total == 0}


@app.post("/api/admin/setup")
def admin_setup(data: AdminSetupIn, request: Request):
    conn = db()

    try:
        if admin_count(conn) > 0:
            raise HTTPException(
                status_code=409,
                detail="Administrator sudah diinisialisasi."
            )

        username = data.username.strip()

        if not username:
            raise HTTPException(status_code=400, detail="Username admin wajib diisi.")

        conn.execute(
            """
            INSERT INTO administrators
            (
                username,
                password_hash,
                created_at
            )
            VALUES
            (?, ?, ?)
            """,
            (
                username,
                hash_password(data.password),
                now_iso(),
            ),
        )

        record_admin_audit(
            conn,
            username,
            "ADMIN_INITIALIZED",
            detail={"username": username},
        )

        conn.commit()

        clear_login_failures(
            login_bucket(request, f"admin:{username}")
        )

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return {
        "token": sign_admin_token(username),
        "username": username,
    }


@app.post("/api/admin/login")
def admin_login(data: AdminLoginIn, request: Request):
    username = data.username.strip()

    rate_key = check_login_rate(request, f"admin:{username}")

    conn = db()
    row = conn.execute(
        """
        SELECT username, password_hash
        FROM administrators
        WHERE username=?
        """,
        (
            username,
        ),
    ).fetchone()

    valid, replacement_hash = (
        verify_and_rehash(data.password, row["password_hash"])
        if row
        else (False, None)
    )

    if not valid:
        conn.close()
        record_login_failure(rate_key)
        raise HTTPException(status_code=401, detail="Username atau password admin salah.")

    if replacement_hash:
        conn.execute(
            "UPDATE administrators SET password_hash=?, updated_at=? WHERE username=?",
            (replacement_hash, now_iso(), row["username"]),
        )
        conn.commit()

    conn.close()

    clear_login_failures(rate_key)

    return {
        "token": sign_admin_token(row["username"]),
        "username": row["username"],
    }


@app.get("/api/admin/me")
def admin_me(admin_username: str = Depends(current_admin)):
    return {"username": admin_username}


@app.post("/api/admin/session/refresh")
def refresh_admin_session(admin_username: str = Depends(current_admin)):
    """Perpanjang jendela idle admin setelah aktivitas nyata di browser."""
    return {
        "token": sign_admin_token(admin_username),
        "username": admin_username,
        "idle_timeout_seconds": ADMIN_SESSION_SECONDS,
    }


@app.post("/api/admin/change-password")
def admin_change_password(
    data: AdminPasswordChangeIn,
    admin_username: str = Depends(current_admin),
):
    conn = db()

    try:
        row = conn.execute(
            """
            SELECT password_hash
            FROM administrators
            WHERE username=?
            """,
            (
                admin_username,
            ),
        ).fetchone()

        if not row or not verify_password(data.current_password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Password admin saat ini salah.")

        conn.execute(
            """
            UPDATE administrators
            SET password_hash=?,
                updated_at=?
            WHERE username=?
            """,
            (
                hash_password(data.new_password),
                now_iso(),
                admin_username,
            ),
        )

        record_admin_audit(
            conn,
            admin_username,
            "ADMIN_PASSWORD_CHANGED",
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return {"ok": True}


@app.get("/api/admin/users")
def admin_users(admin_username: str = Depends(current_admin)):
    conn = db()

    rows = conn.execute(
        """
        SELECT
            username,
            display_name,
            nip,
            rank,
            position,
            public_key,
            pki_public_key,
            account_status,
            certificate_status,
            created_at,
            approved_at,
            approved_by,
            revoked_at,
            revoked_by,
            deleted_at,
            deleted_by
        FROM users
        ORDER BY created_at DESC, username ASC
        """
    ).fetchall()

    conn.close()

    users_result = [
        user_admin_view(row)
        for row in rows
    ]

    account_groups = {
        status: [
            user for user in users_result
            if user["account_status"] == status
        ]
        for status in ACCOUNT_STATUSES
    }

    certificate_groups = {
        status: [
            user for user in users_result
            if user["certificate_status"] == status
        ]
        for status in CERTIFICATE_STATUSES
    }

    return {
        "account_statuses": list(ACCOUNT_STATUSES),
        "certificate_statuses": list(CERTIFICATE_STATUSES),
        "users": users_result,
        "account_groups": account_groups,
        "certificate_groups": certificate_groups,
    }



@app.patch("/api/admin/users/{target_username}")
def admin_edit_user(
    target_username: PathUsername,
    data: AdminUserEditIn,
    admin_username: str = Depends(current_admin),
):
    conn = db()

    try:
        row = conn.execute(
            "SELECT username FROM users WHERE username=?",
            (target_username,),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="User tidak ditemukan.")

        conn.execute(
            """
            UPDATE users
            SET display_name=?,
                nip=?,
                rank=?,
                position=?
            WHERE username=?
            """,
            (
                data.display_name.strip(),
                data.nip.strip(),
                data.rank.strip(),
                data.position.strip(),
                target_username,
            ),
        )

        record_admin_audit(
            conn,
            admin_username,
            "USER_METADATA_EDITED",
            target_username,
            {
                "display_name": data.display_name.strip(),
                "nip": data.nip.strip(),
                "rank": data.rank.strip(),
                "position": data.position.strip(),
            },
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return {"ok": True}


@app.post("/api/admin/users/{target_username}/approve")
def admin_approve_user(
    target_username: PathUsername,
    admin_username: str = Depends(current_admin),
):
    conn = db()

    try:

        user = conn.execute(
            """
            SELECT account_status
            FROM users
            WHERE username=?
            """,
            (
                target_username,
            ),
        ).fetchone()

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User tidak ditemukan."
            )

        if user["account_status"] == "DELETED":
            raise HTTPException(
                status_code=400,
                detail="User deleted harus direstore terlebih dahulu."
            )

        conn.execute(
            """
            UPDATE users
            SET
                account_status='ACTIVE',
                approved_at=?,
                approved_by=?,
                revoked_at=NULL,
                revoked_by=NULL,
                deleted_at=NULL,
                deleted_by=NULL
            WHERE username=?
            """,
            (
                now_iso(),
                admin_username,
                target_username,
            ),
        )


        record_admin_audit(
            conn,
            admin_username,
            "USER_APPROVED",
            target_username,
        )

        conn.commit()

    except Exception:

        conn.rollback()

        raise

    finally:

        conn.close()

    return {
        "ok": True
    }


@app.post("/api/admin/users/{target_username}/reject")
def admin_reject_user(
    target_username: PathUsername,
    data: AdminUserReasonIn,
    admin_username: str = Depends(current_admin),
):
    conn = db()

    try:
        user = conn.execute(
            "SELECT account_status FROM users WHERE username=?",
            (target_username,),
        ).fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User tidak ditemukan.")

        if user["account_status"] == "DELETED":
            raise HTTPException(status_code=400, detail="User deleted harus direstore terlebih dahulu.")

        conn.execute(
            """
            UPDATE users
            SET account_status='REJECTED',
                revoked_at=NULL,
                revoked_by=NULL,
                deleted_at=NULL,
                deleted_by=NULL
            WHERE username=?
            """,
            (
                target_username,
            ),
        )

        record_admin_audit(
            conn,
            admin_username,
            "USER_REJECTED",
            target_username,
            {"reason": data.reason or ""},
        )
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return {"ok": True}


@app.post("/api/admin/users/{target_username}/revoke")
def admin_revoke_user(
    target_username: PathUsername,
    data: AdminUserReasonIn,
    admin_username: str = Depends(current_admin),
):
    conn = db()

    try:
        user = conn.execute(
            "SELECT account_status FROM users WHERE username=?",
            (target_username,),
        ).fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User tidak ditemukan.")

        if user["account_status"] == "DELETED":
            raise HTTPException(status_code=400, detail="User deleted harus direstore terlebih dahulu.")

        conn.execute(
            """
            UPDATE users
            SET account_status='REJECTED',
                revoked_at=?,
                revoked_by=?,
                deleted_at=NULL,
                deleted_by=NULL
            WHERE username=?
            """,
            (
                now_iso(),
                admin_username,
                target_username,
            ),
        )

        record_admin_audit(
            conn,
            admin_username,
            "USER_REVOKED",
            target_username,
            {"reason": data.reason or ""},
        )
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return {"ok": True}


@app.post("/api/admin/users/{target_username}/restore")
def admin_restore_user(
    target_username: PathUsername,
    admin_username: str = Depends(current_admin),
):
    conn = db()

    try:
        user = conn.execute(
            "SELECT account_status FROM users WHERE username=?",
            (target_username,),
        ).fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User tidak ditemukan.")

        if user["account_status"] not in {"REJECTED", "DELETED"}:
            raise HTTPException(status_code=400, detail="Hanya user rejected atau deleted yang bisa direstore.")

        conn.execute(
            """
            UPDATE users
            SET account_status='ACTIVE',
                approved_at=COALESCE(approved_at, ?),
                approved_by=COALESCE(approved_by, ?),
                revoked_at=NULL,
                revoked_by=NULL,
                deleted_at=NULL,
                deleted_by=NULL
            WHERE username=?
            """,
            (
                now_iso(),
                admin_username,
                target_username,
            ),
        )

        record_admin_audit(conn, admin_username, "USER_RESTORED", target_username)
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return {"ok": True}


@app.post("/api/admin/users/{target_username}/soft-delete")
def admin_soft_delete_user(
    target_username: PathUsername,
    admin_username: str = Depends(current_admin),
):
    conn = db()

    try:
        if not conn.execute("SELECT 1 FROM users WHERE username=?", (target_username,)).fetchone():
            raise HTTPException(status_code=404, detail="User tidak ditemukan.")

        conn.execute(
            """
            UPDATE users
            SET account_status='DELETED',
                deleted_at=?,
                deleted_by=?
            WHERE username=?
            """,
            (
                now_iso(),
                admin_username,
                target_username,
            ),
        )

        record_admin_audit(conn, admin_username, "USER_SOFT_DELETED", target_username)
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return {"ok": True}


@app.post("/api/register")
def register(data: RegisterIn):
    validate_dipp_public_identity(data.public_key, data.username)
    validate_pki_public_key(data.pki_public_key)
    conn = db()

    try:

        conn.execute(
            """
            INSERT INTO users
            (
                username,
                display_name,
                password_hash,

                nip,
                rank,
                position,

                public_key,
                pki_public_key,

                account_status,
                certificate_status,

                created_at
            )
            VALUES
            (
                ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?,
                ?
            )
            """,
            (
                data.username,
                data.display_name,
                hash_password(data.password),

                data.nip,
                data.rank,
                data.position,

                json.dumps(data.public_key),
                data.pki_public_key,

                "PENDING",
                "NONE",

                now_iso(),
            ),
        )

        conn.commit()

    except sqlite3.IntegrityError as exc:

        raise HTTPException(
            status_code=409,
            detail="Username sudah dipakai."
        ) from exc

    finally:

        conn.close()

    return {
        "username": data.username,
        "account_status": "PENDING",
        "message": "Registrasi berhasil. Akun sedang menunggu approval administrator.",
    }


@app.post("/api/login")
def login(
    data: LoginIn,
    request: Request,
):
    """Tahap awal login: password diperiksa, tetapi JWT utama belum diterbitkan."""

    username = data.username.strip()
    rate_key = check_login_rate(request, username)
    conn = db()

    row = conn.execute(
        """
        SELECT password_hash, account_status
        FROM users
        WHERE username=?
        """,
        (username,),
    ).fetchone()

    valid, replacement_hash = (
        verify_and_rehash(data.password, row["password_hash"])
        if row
        else (False, None)
    )

    if not valid:
        conn.close()
        record_login_failure(rate_key)
        raise HTTPException(
            status_code=401,
            detail="Username atau password salah.",
        )

    if replacement_hash:
        conn.execute(
            "UPDATE users SET password_hash=? WHERE username=?",
            (replacement_hash, username),
        )
        conn.commit()

    if row["account_status"] != "ACTIVE":
        conn.close()
        enforce_active_account(row["account_status"])

    clear_login_failures(rate_key)

    cert = conn.execute(
        """
        SELECT serial_number, status, expires_at
        FROM certificates
        WHERE username=?
        ORDER BY issued_at DESC
        LIMIT 1
        """,
        (username,),
    ).fetchone()

    certificate_status = "NONE"

    if cert:
        certificate_status = cert["status"]

        if (
            cert["status"] == "ACTIVE"
            and datetime.fromisoformat(cert["expires_at"])
            <= datetime.now(timezone.utc)
        ):
            certificate_status = "EXPIRED"
            conn.execute(
                "UPDATE certificates SET status='EXPIRED' WHERE serial_number=?",
                (cert["serial_number"],),
            )
            conn.execute(
                "UPDATE users SET certificate_status='EXPIRED' WHERE username=?",
                (username,),
            )
            conn.commit()
        elif cert["status"] == "ACTIVE":
            certificate_status = "ISSUED"

    conn.close()

    return {
        "login_token": sign_pending_login_token(username),
        "username": username,
        "account_status": row["account_status"],
        "certificate_status": certificate_status,
        "next": "RSA_CHALLENGE",
    }


@app.post("/api/login/challenge")
def login_challenge(
    username: str = Depends(current_pending_login_user),
):
    nonce = secrets.token_hex(32)
    conn = db()

    conn.execute(
        """
        INSERT OR REPLACE INTO certificate_challenges
        (username, nonce, created_at)
        VALUES (?, ?, ?)
        """,
        (username, nonce, now_iso()),
    )

    conn.commit()
    conn.close()
    return {"nonce": nonce}


@app.post("/api/login/verify")
def login_verify(
    data: LoginVerifyIn,
    username: str = Depends(current_pending_login_user),
):
    """RSA proof setiap login; login pertama sekaligus mengaktifkan certificate."""

    conn = db()

    try:
        challenge = conn.execute(
            "SELECT nonce FROM certificate_challenges WHERE username=?",
            (username,),
        ).fetchone()

        if not challenge:
            raise HTTPException(
                status_code=400,
                detail="Challenge login tidak ditemukan.",
            )

        if challenge["nonce"] != data.nonce:
            raise HTTPException(
                status_code=400,
                detail="Challenge login tidak valid.",
            )

        user = conn.execute(
            """
            SELECT account_status, pki_public_key
            FROM users
            WHERE username=?
            """,
            (username,),
        ).fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User tidak ditemukan.")

        enforce_active_account(user["account_status"])

        if not user["pki_public_key"]:
            raise HTTPException(
                status_code=400,
                detail="RSA Public Key user belum tersedia.",
            )

        if user["pki_public_key"].strip() != data.public_key_pem.strip():
            raise HTTPException(
                status_code=401,
                detail="RSA Login Key bukan milik user ini.",
            )

        if not verify_pki_signature(
            user["pki_public_key"],
            data.nonce,
            data.signature,
        ):
            raise HTTPException(
                status_code=401,
                detail="Proof of Possession RSA tidak valid.",
            )

        latest_cert = conn.execute(
            """
            SELECT serial_number, status, expires_at
            FROM certificates
            WHERE username=?
            ORDER BY issued_at DESC
            LIMIT 1
            """,
            (username,),
        ).fetchone()

        certificate_issued = False
        certificate_serial = None

        if not latest_cert or latest_cert["status"] == "REPLACED":
            issued = issue_certificate_core(conn, username)
            certificate_issued = True
            certificate_serial = issued["serial_number"]

        else:
            certificate_serial = latest_cert["serial_number"]

            if latest_cert["status"] != "ACTIVE":
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Certificate akun tidak aktif: "
                        + latest_cert["status"]
                    ),
                )

            if (
                datetime.fromisoformat(latest_cert["expires_at"])
                <= datetime.now(timezone.utc)
            ):
                conn.execute(
                    "UPDATE certificates SET status='EXPIRED' WHERE serial_number=?",
                    (latest_cert["serial_number"],),
                )
                conn.execute(
                    "UPDATE users SET certificate_status='EXPIRED' WHERE username=?",
                    (username,),
                )
                raise HTTPException(
                    status_code=403,
                    detail="Certificate akun sudah expired.",
                )

            conn.execute(
                "UPDATE users SET certificate_status='ISSUED' WHERE username=?",
                (username,),
            )

        conn.execute(
            "DELETE FROM certificate_challenges WHERE username=?",
            (username,),
        )
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return {
        "token": sign_token(username),
        "username": username,
        "account_status": "ACTIVE",
        "certificate_status": "ISSUED",
        "certificate_issued": certificate_issued,
        "certificate_serial": certificate_serial,
    }


def issue_certificate_core(
    conn: sqlite3.Connection,
    target_username: str,
):
    """
    Engine penerbitan certificate.
    Dipakai oleh:
    - Administrator
    - Auto Enrollment
    """

    # ===================================================
    # Pastikan belum punya certificate aktif
    # ===================================================

    existing = conn.execute(
        """
        SELECT serial_number
        FROM certificates
        WHERE username=?
        AND status='ACTIVE'
        """,
        (
            target_username,
        ),
    ).fetchone()

    if existing:
        raise HTTPException(
            status_code=400,
            detail="User sudah memiliki certificate aktif."
        )

    # ===================================================
    # Ambil Public Key User
    # ===================================================

    user = conn.execute(
        """
        SELECT
            pki_public_key
        FROM users
        WHERE username=?
        """,
        (
            target_username,
        ),
    ).fetchone()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User tidak ditemukan."
        )

    if not user["pki_public_key"]:
        raise HTTPException(
            status_code=400,
            detail="PKI Public Key belum tersedia."
        )

    # ===================================================
    # Issue Certificate
    # ===================================================

    cert_path = issue_certificate(

        target_username,

        user["pki_public_key"]

    )

    certificate_pem = Path(
        cert_path
    ).read_text(
        encoding="utf-8"
    )

    cert = x509.load_pem_x509_certificate(
        certificate_pem.encode("utf-8")
    )

    serial_number = format(cert.serial_number, "X")
    expires_at = cert.not_valid_after_utc.isoformat()

    conn.execute(
        """
        INSERT INTO certificates
        (
            serial_number,
            username,
            certificate_pem,
            issued_at,
            expires_at,
            status
        )
        VALUES
        (?, ?, ?, ?, ?, ?)
        """,
        (
            serial_number,
            target_username,
            certificate_pem,
            cert.not_valid_before_utc.isoformat(),
            expires_at,
            "ACTIVE",
        ),
    )

    conn.execute(
        "UPDATE users SET certificate_status='ISSUED' WHERE username=?",
        (target_username,),
    )

    return {
        "certificate_pem": certificate_pem,
        "public_key_pem": user["pki_public_key"],
        "serial_number": serial_number,
        "expires_at": expires_at,
    }


@app.get("/api/certificate/me")
def certificate_me(
    username: str = Depends(current_user),
):

    conn = db()

    row = conn.execute(
        """
        SELECT
            serial_number,
            certificate_pem,
            issued_at,
            expires_at,
            status
        FROM certificates
        WHERE username=?
        ORDER BY issued_at DESC
        LIMIT 1
        """,
        (
            username,
        ),
    ).fetchone()

    conn.close()

    if not row:

        return {
            "status": "NONE"
        }

    return {

        "status":
            row["status"],

        "serial_number":
            row["serial_number"],

        "issued_at":
            row["issued_at"],

        "expires_at":
            row["expires_at"],

        "certificate_pem":
            row["certificate_pem"]

    }

@app.get("/api/me")
def me(username: str = Depends(current_user)):
    conn = db()
    row = conn.execute(
        "SELECT username, display_name, public_key, created_at FROM users WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()
    return dict(row) | {"public_key": json.loads(row["public_key"])}


@app.post("/api/session/refresh")
def refresh_user_session(username: str = Depends(current_user)):
    """Perpanjang jendela idle user setelah aktivitas nyata di browser."""
    return {
        "token": sign_token(username),
        "username": username,
        "idle_timeout_seconds": SESSION_SECONDS,
    }


@app.get("/api/users")
def users(username: str = Depends(current_user)):
    conn = db()
    rows = conn.execute(
        "SELECT username, display_name, public_key FROM users WHERE username != ? ORDER BY display_name",
        (username,),
    ).fetchall()
    conn.close()
    return [
        {"username": r["username"], "display_name": r["display_name"], "public_key": json.loads(r["public_key"])}
        for r in rows
    ]


@app.get("/api/users/{target_username}/public-key")
def user_public_key(target_username: PathUsername, username: str = Depends(current_user)):
    conn = db()
    row = conn.execute(
        "SELECT username, display_name, public_key FROM users WHERE username=?",
        (target_username,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")
    return {"username": row["username"], "display_name": row["display_name"], "public_key": json.loads(row["public_key"])}


@app.get("/api/users/{target_username}/pki-public-key")
def user_pki_public_key(target_username: PathUsername, username: str = Depends(current_user)):
    conn = db()
    row = conn.execute(
        "SELECT username, pki_public_key, account_status FROM users WHERE username=?",
        (target_username,),
    ).fetchone()
    conn.close()
    if not row or row["account_status"] != "ACTIVE":
        raise HTTPException(status_code=404, detail="Public signing key user aktif tidak ditemukan.")
    return {"username": row["username"], "pki_public_key": row["pki_public_key"]}


@app.get("/api/file-catalog")
def file_catalog(username: str = Depends(current_user)):
    """Metadata file publik internal; tidak pernah mengirim envelope atau key."""

    conn = db()
    rows = conn.execute(
        """
        SELECT
            f.id,
            f.owner,
            u.display_name AS owner_display_name,
            f.filename,
            f.encrypted_size,
            f.created_at,
            EXISTS(
                SELECT 1
                FROM shares s
                WHERE s.file_id=f.id AND s.recipient=?
            ) AS has_access,
            (
                SELECT fr.status
                FROM file_requests fr
                WHERE fr.file_id=f.id AND fr.requester=?
                ORDER BY fr.requested_at DESC, fr.rowid DESC
                LIMIT 1
            ) AS request_status
        FROM files f
        JOIN users u ON u.username=f.owner
        WHERE f.is_hidden=0
          AND f.owner<>?
          AND u.account_status='ACTIVE'
        ORDER BY u.display_name, f.created_at DESC
        """,
        (username, username, username),
    ).fetchall()
    conn.close()
    return [
        dict(row) | {
            "has_access": bool(row["has_access"]),
        }
        for row in rows
    ]


@app.get("/api/file-requests")
def list_file_requests(username: str = Depends(current_user)):
    conn = db()
    incoming = conn.execute(
        """
        SELECT
            fr.id,
            fr.file_id,
            fr.requester,
            u.display_name AS requester_display_name,
            f.filename,
            fr.status,
            fr.requested_at
        FROM file_requests fr
        JOIN files f ON f.id=fr.file_id
        JOIN users u ON u.username=fr.requester
        WHERE fr.owner=? AND fr.status='PENDING'
        ORDER BY fr.requested_at DESC
        """,
        (username,),
    ).fetchall()
    outgoing = conn.execute(
        """
        SELECT
            fr.id,
            fr.file_id,
            fr.owner,
            u.display_name AS owner_display_name,
            f.filename,
            fr.status,
            fr.requested_at,
            fr.resolved_at
        FROM file_requests fr
        JOIN files f ON f.id=fr.file_id
        JOIN users u ON u.username=fr.owner
        WHERE fr.requester=?
        ORDER BY fr.requested_at DESC
        LIMIT 100
        """,
        (username,),
    ).fetchall()
    conn.close()
    return {
        "incoming": [dict(row) for row in incoming],
        "outgoing": [dict(row) for row in outgoing],
    }


@app.post("/api/files/{file_id}/requests")
def create_file_request(file_id: PathOpaqueId, username: str = Depends(current_user)):
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    file_row = conn.execute(
        "SELECT id, owner, is_hidden FROM files WHERE id=?",
        (file_id,),
    ).fetchone()

    if not file_row or file_row["is_hidden"]:
        conn.close()
        raise HTTPException(status_code=404, detail="File tidak tersedia di katalog.")
    if file_row["owner"] == username:
        conn.close()
        raise HTTPException(status_code=400, detail="Pemilik tidak perlu meminta file sendiri.")
    if conn.execute(
        "SELECT 1 FROM shares WHERE file_id=? AND recipient=?",
        (file_id, username),
    ).fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="Anda sudah memiliki akses file.")
    if conn.execute(
        "SELECT 1 FROM file_requests WHERE file_id=? AND requester=? AND status='PENDING'",
        (file_id, username),
    ).fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="Permintaan file masih menunggu persetujuan.")

    request_id = new_id()
    try:
        conn.execute(
            """
            INSERT INTO file_requests (
                id, file_id, owner, requester, status, requested_at
            ) VALUES (?, ?, ?, ?, 'PENDING', ?)
            """,
            (request_id, file_id, file_row["owner"], username, now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(
            status_code=409,
            detail="Permintaan file masih menunggu persetujuan.",
        ) from exc
    finally:
        conn.close()

    return {"id": request_id, "status": "PENDING"}


@app.post("/api/file-requests/{request_id}/approve")
def approve_file_request(
    request_id: PathOpaqueId,
    data: FileRequestApprovalIn,
    username: str = Depends(current_user),
):
    validate_dipp_wrapped_key(data.wrapped_key)
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    request_row = conn.execute(
        """
        SELECT fr.id, fr.file_id, fr.owner, fr.requester, fr.status,
               u.account_status AS requester_status
        FROM file_requests fr
        JOIN users u ON u.username=fr.requester
        WHERE fr.id=?
        """,
        (request_id,),
    ).fetchone()

    if not request_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Permintaan file tidak ditemukan.")
    if request_row["owner"] != username:
        conn.close()
        raise HTTPException(status_code=403, detail="Hanya pemilik file yang dapat menyetujui.")
    if request_row["status"] != "PENDING":
        conn.close()
        raise HTTPException(status_code=409, detail="Permintaan file sudah diproses.")
    if request_row["requester_status"] != "ACTIVE":
        conn.close()
        raise HTTPException(status_code=409, detail="Akun peminta tidak aktif.")
    if (
        data.wrapped_key["sender_id"] != username
        or data.wrapped_key["recipient_id"] != request_row["requester"]
    ):
        conn.close()
        raise HTTPException(status_code=400, detail="Wrapped key approval tidak terikat ke peminta.")
    if data.wrapped_key["file_context_id"] != stored_file_context(request_row["file_id"]):
        conn.close()
        raise HTTPException(status_code=400, detail="File context wrapped key approval tidak cocok.")

    existing_share = conn.execute(
        "SELECT 1 FROM shares WHERE file_id=? AND recipient=?",
        (request_row["file_id"], request_row["requester"]),
    ).fetchone()
    if not existing_share:
        register_dipp_ciphertext(conn, data.wrapped_key, username, request_row["requester"])
        conn.execute(
            """
            INSERT INTO shares (
                id, file_id, owner, recipient, wrapped_key, permission, created_at
            ) VALUES (?, ?, ?, ?, ?, 'viewer', ?)
            """,
            (
                new_id(),
                request_row["file_id"],
                username,
                request_row["requester"],
                json.dumps(data.wrapped_key),
                now_iso(),
            ),
        )
    conn.execute(
        "UPDATE file_requests SET status='APPROVED', resolved_at=? WHERE id=?",
        (now_iso(), request_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "status": "APPROVED"}


@app.post("/api/file-requests/{request_id}/reject")
def reject_file_request(request_id: PathOpaqueId, username: str = Depends(current_user)):
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    request_row = conn.execute(
        "SELECT owner, status FROM file_requests WHERE id=?",
        (request_id,),
    ).fetchone()
    if not request_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Permintaan file tidak ditemukan.")
    if request_row["owner"] != username:
        conn.close()
        raise HTTPException(status_code=403, detail="Hanya pemilik file yang dapat menolak.")
    if request_row["status"] != "PENDING":
        conn.close()
        raise HTTPException(status_code=409, detail="Permintaan file sudah diproses.")

    conn.execute(
        "UPDATE file_requests SET status='REJECTED', resolved_at=? WHERE id=?",
        (now_iso(), request_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "status": "REJECTED"}


@app.post("/api/upload/start")
def upload_start(
    data: UploadStartIn,
    username: str = Depends(current_user)
):
    cleanup_upload_sessions()

    expected_total_chunks = (
        data.file_size + data.chunk_size - 1
    ) // data.chunk_size
    if data.total_chunks != expected_total_chunks:
        raise HTTPException(
            status_code=400,
            detail="total_chunks tidak sesuai ukuran ciphertext dan chunk.",
        )

    upload_id = new_id()

    upload_dir = TEMP_UPLOAD_DIR / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    conn = db()

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(hours=24)
    ).isoformat(timespec="seconds")

    conn.execute(
        """
        INSERT INTO upload_sessions (
            id,
            owner,
            filename,
            file_size,
            chunk_size,
            total_chunks,
            uploaded_chunks,
            created_at,
            expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            upload_id,
            username,
            data.filename,
            data.file_size,
            data.chunk_size,
            data.total_chunks,
            0,
            now_iso(),
            expires_at,
        )
    )

    conn.commit()
    conn.close()

    return {
        "upload_id": upload_id
    }

@app.post("/api/upload/chunk")
def upload_chunk(
    data: UploadChunkIn,
    username: str = Depends(current_user)
):

    conn = db()

    row = conn.execute(
        """
        SELECT owner, file_size, chunk_size, total_chunks
        FROM upload_sessions
        WHERE id = ?;
        """,
        (data.upload_id,)
    ).fetchone()

    if row is None:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Upload session tidak ditemukan."
        )

    if row["owner"] != username:
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Upload session bukan milik Anda."
        )

    if data.chunk_index >= row["total_chunks"]:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="chunk_index melebihi total_chunks."
        )

    if data.total_chunks != row["total_chunks"]:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="total_chunks tidak cocok dengan sesi upload.",
        )

    upload_dir = TEMP_UPLOAD_DIR / data.upload_id

    if not upload_dir.exists():
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Folder upload tidak ditemukan."
        )

    chunk_path = (
        upload_dir /
        f"chunk_{data.chunk_index:06d}.bin"
    )
    temp_chunk_path = None

    try:
        chunk_bytes = base64.b64decode(data.data_b64, validate=True)

        expected_size = min(
            row["chunk_size"],
            row["file_size"] - (data.chunk_index * row["chunk_size"]),
        )
        if expected_size <= 0 or len(chunk_bytes) != expected_size:
            raise HTTPException(
                status_code=400,
                detail="Ukuran chunk tidak sesuai metadata sesi upload.",
            )

        # Upload ulang chunk yang sudah lengkap bersifat idempotent.
        if chunk_path.exists():
            if chunk_path.stat().st_size != expected_size:
                raise HTTPException(
                    status_code=409,
                    detail="Chunk yang tersimpan memiliki ukuran tidak konsisten.",
                )
            return {
                "message": "Chunk already received.",
                "chunk": data.chunk_index,
                "received": expected_size,
            }

        temp_chunk_path = upload_dir / f".chunk_{data.chunk_index:06d}.tmp"
        temp_chunk_path.write_bytes(chunk_bytes)
        temp_chunk_path.replace(chunk_path)

        conn.execute(
            """
            UPDATE upload_sessions
            SET uploaded_chunks = uploaded_chunks + 1
            WHERE id = ?;
            """,
            (data.upload_id,)
        )

        conn.commit()

    except HTTPException:

        conn.rollback()

        raise

    except (binascii.Error, ValueError, TypeError) as e:

        conn.rollback()

        raise HTTPException(
            status_code=400,
            detail="Data Base64 chunk tidak valid.",
        ) from e

    except Exception as e:

        conn.rollback()

        print(f"[Upload] Gagal menyimpan chunk: {type(e).__name__}")

        raise HTTPException(
            status_code=500,
            detail="Gagal menyimpan chunk."
        )

    finally:

        if temp_chunk_path is not None and temp_chunk_path.exists():
            temp_chunk_path.unlink()

        conn.close()

    return {
        "chunk": data.chunk_index,
        "received": len(chunk_bytes)
    }

@app.post("/api/upload/finish")
def upload_finish(
    data: UploadFinishIn,
    username: str = Depends(current_user)
):
    validate_dipp_wrapped_key(data.wrapped_key_for_owner)
    if (
        data.wrapped_key_for_owner["sender_id"] != username
        or data.wrapped_key_for_owner["recipient_id"] != username
    ):
        raise HTTPException(status_code=400, detail="Wrapped key owner tidak terikat ke pemilik.")
    conn = db()
    upload_dir = TEMP_UPLOAD_DIR / data.upload_id
    target_dir = None
    moved_to_storage = False

    try:
        row = conn.execute(
            """
            SELECT
                owner,
                filename,
                file_size,
                chunk_size,
                uploaded_chunks,
                total_chunks
            FROM upload_sessions
            WHERE id = ?;
            """,
            (data.upload_id,)
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Upload session tidak ditemukan."
            )

        if row["owner"] != username:
            raise HTTPException(
                status_code=403,
                detail="Upload session bukan milik Anda."
            )

        validate_file_envelope(
            data.envelope,
            expected_filename=row["filename"],
            expected_version=1,
            allow_ciphertext=False,
        )
        if data.wrapped_key_for_owner["file_context_id"] != data.envelope["file_context_id"]:
            raise HTTPException(status_code=400, detail="File context wrapped key tidak cocok dengan envelope.")
        decode_standard_b64(
            data.ciphertext_sha256,
            "ciphertext_sha256",
            max_bytes=32,
            exact_bytes=32,
        )
        register_dipp_ciphertext(conn, data.wrapped_key_for_owner, username, username)

        if not upload_dir.exists():
            raise HTTPException(
                status_code=404,
                detail="Folder upload tidak ditemukan.",
            )

        expected_paths = [
            upload_dir / f"chunk_{index:06d}.bin"
            for index in range(row["total_chunks"])
        ]
        if (
            row["uploaded_chunks"] != row["total_chunks"]
            or any(not path.is_file() for path in expected_paths)
        ):
            raise HTTPException(
                status_code=409,
                detail="Masih ada chunk yang belum diterima."
            )

        digest = hashlib.sha256()
        ciphertext_size = 0
        for index, chunk_file in enumerate(expected_paths):
            expected_size = min(
                row["chunk_size"],
                row["file_size"] - (index * row["chunk_size"]),
            )
            actual_size = chunk_file.stat().st_size
            if expected_size <= 0 or actual_size != expected_size:
                raise HTTPException(
                    status_code=409,
                    detail=f"Ukuran chunk {index} tidak konsisten.",
                )
            ciphertext_size += actual_size
            with chunk_file.open("rb") as source:
                while block := source.read(1024 * 1024):
                    digest.update(block)

        if ciphertext_size != row["file_size"]:
            raise HTTPException(
                status_code=409,
                detail="Ukuran ciphertext gabungan tidak sesuai sesi upload.",
            )

        for temporary_path in upload_dir.glob(".chunk_*.tmp"):
            temporary_path.unlink()

        server_sha256 = base64.b64encode(digest.digest()).decode("ascii")
        if not hmac.compare_digest(server_sha256, data.ciphertext_sha256):
            raise HTTPException(
                status_code=409,
                detail="Integrity check gagal. Ciphertext berubah selama upload."
            )

        file_id = new_id()
        envelope = data.envelope.copy()
        envelope.pop("ciphertext_b64", None)
        envelope["file_id"] = file_id
        envelope["version"] = 1
        envelope["uploaded_at"] = now_iso()
        envelope["storage_format"] = FILE_STORAGE_FORMAT
        envelope["chunk_size"] = row["chunk_size"]
        envelope["total_chunks"] = row["total_chunks"]
        envelope["ciphertext_size"] = ciphertext_size
        envelope["ciphertext_sha256"] = server_sha256

        (upload_dir / "envelope.json").write_text(
            json.dumps(
                envelope,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

        target_dir = file_storage_dir(file_id)
        if target_dir.exists():
            raise RuntimeError("Folder penyimpanan file sudah ada.")
        upload_dir.replace(target_dir)
        moved_to_storage = True

        conn.execute(
            """
            INSERT INTO files
            (
                id,
                owner,
                filename,
                envelope_name,
                encrypted_size,
                is_hidden,
                storage_format,
                chunk_size,
                total_chunks,
                ciphertext_size,
                ciphertext_sha256,
                created_at
            )
            VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                username,
                row["filename"],
                "envelope.json",
                ciphertext_size,
                int(data.is_hidden),
                FILE_STORAGE_FORMAT,
                row["chunk_size"],
                row["total_chunks"],
                ciphertext_size,
                server_sha256,
                now_iso(),
            ),
        )

        conn.execute(
            """
            INSERT INTO shares
            (
                id,
                file_id,
                owner,
                recipient,
                wrapped_key,
                permission,
                created_at
            )
            VALUES
            (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id(),
                file_id,
                username,
                username,
                json.dumps(data.wrapped_key_for_owner),
                "owner",
                now_iso(),
            ),
        )

        conn.execute(
            "DELETE FROM upload_sessions WHERE id=?",
            (data.upload_id,),
        )
        conn.commit()

    except Exception:
        conn.rollback()
        if moved_to_storage and target_dir is not None and target_dir.exists():
            if upload_dir.exists():
                shutil.rmtree(upload_dir, ignore_errors=True)
            target_dir.replace(upload_dir)
            moved_to_storage = False
        pending_envelope = upload_dir / "envelope.json"
        if pending_envelope.exists():
            pending_envelope.unlink()
        raise

    finally:
        conn.close()

    return {
        "file_id": file_id,
        "storage_format": FILE_STORAGE_FORMAT,
        "total_chunks": row["total_chunks"],
    }

@app.get("/api/files")
def list_files(username: str =Depends(current_user)):

    conn = db()

    rows = conn.execute(
        """
        SELECT
            f.id,
            f.owner,
            f.filename,
            f.encrypted_size,
            f.is_hidden,
            f.storage_format,
            f.chunk_size,
            f.total_chunks,
            f.ciphertext_size,
            f.ciphertext_sha256,
            f.created_at,
            f.envelope_name,
            s.permission
        FROM files f
        JOIN shares s
            ON s.file_id = f.id
        WHERE s.recipient = ?
        GROUP BY f.id
        ORDER BY f.created_at DESC
        """,
        (username,)
    ).fetchall()

    result = []

    for row in rows:

        item = dict(row)

        try:

            env_path = envelope_path(
                row["id"],
                create_dir=False
            )

            item["envelope"] = json.loads(
                env_path.read_text(
                    encoding="utf-8"
                )
            )

        except Exception:

            item["envelope"] = {}

        result.append(item)

    conn.close()

    return result

@app.get("/api/files/{file_id}")
def download_file(file_id: PathOpaqueId, username: str = Depends(current_user)):
    conn = db()

    row = conn.execute(
        """
        SELECT f.id, f.owner, f.filename, f.envelope_name,
               f.storage_format, f.chunk_size, f.total_chunks,
               f.ciphertext_size, f.ciphertext_sha256,
               s.wrapped_key, s.permission
        FROM files f
        JOIN shares s
             ON s.file_id = f.id
        WHERE f.id = ?
          AND s.recipient = ?
        """,
        (file_id, username),
    ).fetchone()

    conn.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="File tidak ditemukan atau belum dibagikan ke akun ini."
        )

    env_path = envelope_path(
        row["id"],
        create_dir=False
    )

    return {
        "id": row["id"],
        "owner": row["owner"],
        "filename": row["filename"],
        "permission": row["permission"],
        "envelope": json.loads(env_path.read_text()),
        "wrapped_key": json.loads(row["wrapped_key"]),
        "download": {
            "storage_format": row["storage_format"],
            "chunk_size": row["chunk_size"],
            "total_chunks": row["total_chunks"],
            "ciphertext_size": row["ciphertext_size"],
            "ciphertext_sha256": row["ciphertext_sha256"],
        },
    }


@app.get("/api/files/{file_id}/chunks/{chunk_index}")
def download_file_chunk(
    file_id: PathOpaqueId,
    chunk_index: PathChunkIndex,
    username: str = Depends(current_user),
):
    conn = db()
    row = conn.execute(
        """
        SELECT f.storage_format, f.chunk_size, f.total_chunks, f.ciphertext_size
        FROM files f
        JOIN shares s ON s.file_id=f.id
        WHERE f.id=? AND s.recipient=?
        """,
        (file_id, username),
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="File tidak ditemukan atau belum dibagikan ke akun ini.",
        )
    if row["storage_format"] != FILE_STORAGE_FORMAT:
        raise HTTPException(
            status_code=409,
            detail="Format penyimpanan file tidak mendukung download chunk.",
        )
    if chunk_index < 0 or chunk_index >= row["total_chunks"]:
        raise HTTPException(
            status_code=416,
            detail="Indeks chunk berada di luar rentang file.",
        )

    chunk_file = ciphertext_chunk_path(file_id, chunk_index)
    expected_size = min(
        row["chunk_size"],
        row["ciphertext_size"] - (chunk_index * row["chunk_size"]),
    )
    if (
        expected_size <= 0
        or not chunk_file.is_file()
        or chunk_file.stat().st_size != expected_size
    ):
        raise HTTPException(
            status_code=500,
            detail="Chunk ciphertext tidak tersedia atau tidak konsisten.",
        )

    return FileResponse(
        chunk_file,
        media_type="application/octet-stream",
        headers={
            "X-Chunk-Index": str(chunk_index),
            "X-Total-Chunks": str(row["total_chunks"]),
            "X-Ciphertext-Size": str(row["ciphertext_size"]),
        },
    )

@app.get("/api/files/{file_id}/access")
def file_access(file_id: PathOpaqueId, username: str = Depends(current_user)):
    conn = db()
    require_file_permission(conn, file_id, username, {"owner", "editor", "viewer"})
    rows = conn.execute(
        """
        SELECT u.username, u.display_name, u.public_key, s.permission
        FROM shares s
        JOIN users u ON u.username = s.recipient
        WHERE s.file_id = ?
        ORDER BY CASE s.permission WHEN 'owner' THEN 0 WHEN 'editor' THEN 1 ELSE 2 END, u.display_name
        """,
        (file_id,),
    ).fetchall()
    conn.close()
    return [
        {
            "username": row["username"],
            "display_name": row["display_name"],
            "permission": row["permission"],
            "public_key": json.loads(row["public_key"]),
        }
        for row in rows
    ]


@app.patch("/api/files/{file_id}")
def rename_file(file_id: PathOpaqueId, data: FileRenameIn, username: str = Depends(current_user)):
    conn = db()
    require_file_permission(conn, file_id, username, {"owner", "editor"})
    conn.execute("UPDATE files SET filename=? WHERE id=?", (data.filename, file_id))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.patch("/api/files/{file_id}/visibility")
def update_file_visibility(
    file_id: PathOpaqueId,
    data: FileVisibilityIn,
    username: str = Depends(current_user),
):
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    require_file_permission(conn, file_id, username, {"owner"})
    conn.execute(
        "UPDATE files SET is_hidden=? WHERE id=?",
        (int(data.is_hidden), file_id),
    )
    cancelled = 0
    if data.is_hidden:
        cursor = conn.execute(
            """
            UPDATE file_requests
            SET status='CANCELLED', resolved_at=?
            WHERE file_id=? AND status='PENDING'
            """,
            (now_iso(), file_id),
        )
        cancelled = cursor.rowcount
    conn.commit()
    conn.close()
    return {
        "ok": True,
        "is_hidden": data.is_hidden,
        "cancelled_requests": cancelled,
    }


@app.put("/api/files/{file_id}")
def update_file(file_id: PathOpaqueId, data: FileUpdateIn, username: str = Depends(current_user)):
    conn = db()
    staging_dir = None
    backup_dir = None
    swapped = False

    try:
        require_file_permission(conn, file_id, username, {"owner", "editor"})
        row = conn.execute(
            "SELECT chunk_size, storage_format FROM files WHERE id=?",
            (file_id,),
        ).fetchone()
        if not row or row["storage_format"] != FILE_STORAGE_FORMAT:
            raise HTTPException(
                status_code=409,
                detail="Format penyimpanan file tidak dapat di-update.",
            )

        active_envelope_path = envelope_path(file_id, create_dir=False)
        try:
            if (
                not active_envelope_path.is_file()
                or active_envelope_path.stat().st_size > 64 * 1024
            ):
                raise ValueError
            active_envelope = json.loads(
                active_envelope_path.read_text(encoding="utf-8")
            )
            active_version = active_envelope["version"]
            active_uploaded_at = active_envelope["uploaded_at"]
            if (
                not isinstance(active_version, int)
                or isinstance(active_version, bool)
                or active_version < 1
                or not isinstance(active_uploaded_at, str)
                or len(active_uploaded_at) > 64
            ):
                raise ValueError
            datetime.fromisoformat(active_uploaded_at)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=500,
                detail="Envelope file aktif tidak valid.",
            ) from exc

        ciphertext = validate_file_envelope(
            data.envelope,
            expected_filename=data.filename,
            expected_version=active_version + 1,
            allow_ciphertext=True,
        )
        if data.envelope.get("file_id") not in {None, file_id}:
            raise HTTPException(
                status_code=400,
                detail="file_id envelope tidak cocok dengan target update.",
            )
        recipients = [item.recipient for item in data.wrapped_keys]
        if len(set(recipients)) != len(recipients):
            raise HTTPException(
                status_code=400,
                detail="Penerima wrapped key tidak boleh duplikat.",
            )
        for wrapped_key in data.wrapped_keys:
            validate_dipp_wrapped_key(wrapped_key.wrapped_key)
            if wrapped_key.wrapped_key["recipient_id"] != wrapped_key.recipient:
                raise HTTPException(
                    status_code=400,
                    detail="recipient_id wrapped key tidak cocok.",
                )
            if wrapped_key.wrapped_key["sender_id"] != username:
                raise HTTPException(
                    status_code=400,
                    detail="sender_id wrapped key tidak cocok.",
                )
            if wrapped_key.wrapped_key["file_context_id"] != data.envelope["file_context_id"]:
                raise HTTPException(
                    status_code=400,
                    detail="File context wrapped key tidak cocok dengan envelope.",
                )

        if not ciphertext:
            raise HTTPException(status_code=400, detail="Ciphertext update kosong.")

        chunk_size = row["chunk_size"]
        if chunk_size <= 0:
            raise HTTPException(status_code=500, detail="Metadata chunk file tidak valid.")
        total_chunks = (len(ciphertext) + chunk_size - 1) // chunk_size
        ciphertext_sha256 = base64.b64encode(
            hashlib.sha256(ciphertext).digest()
        ).decode("ascii")

        target_dir = file_storage_dir(file_id)
        staging_dir = target_dir.parent / f".{file_id}.update-{new_id()}"
        backup_dir = target_dir.parent / f".{file_id}.backup-{new_id()}"
        staging_dir.mkdir(parents=False, exist_ok=False)

        envelope = data.envelope.copy()
        envelope.pop("ciphertext_b64", None)
        envelope["file_id"] = file_id
        envelope["uploaded_at"] = active_uploaded_at
        envelope["storage_format"] = FILE_STORAGE_FORMAT
        envelope["chunk_size"] = chunk_size
        envelope["total_chunks"] = total_chunks
        envelope["ciphertext_size"] = len(ciphertext)
        envelope["ciphertext_sha256"] = ciphertext_sha256
        (staging_dir / "envelope.json").write_text(
            json.dumps(envelope, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        for index in range(total_chunks):
            start = index * chunk_size
            end = min(start + chunk_size, len(ciphertext))
            (staging_dir / f"chunk_{index:06d}.bin").write_bytes(
                ciphertext[start:end]
            )

        conn.execute("BEGIN IMMEDIATE")
        require_file_permission(conn, file_id, username, {"owner", "editor"})
        expected_recipients = access_usernames(conn, file_id)
        submitted_recipients = {item.recipient for item in data.wrapped_keys}
        if submitted_recipients != expected_recipients:
            raise HTTPException(
                status_code=400,
                detail="Wrapped key harus dibuat ulang untuk semua user yang masih punya akses.",
            )
        for item in data.wrapped_keys:
            register_dipp_ciphertext(conn, item.wrapped_key, username, item.recipient)

        if not target_dir.is_dir():
            raise HTTPException(status_code=500, detail="Folder file aktif tidak ditemukan.")
        target_dir.replace(backup_dir)
        staging_dir.replace(target_dir)
        swapped = True

        conn.execute(
            """
            UPDATE files
            SET filename=?, encrypted_size=?, total_chunks=?,
                ciphertext_size=?, ciphertext_sha256=?
            WHERE id=?
            """,
            (
                data.filename,
                len(ciphertext),
                total_chunks,
                len(ciphertext),
                ciphertext_sha256,
                file_id,
            ),
        )
        for item in data.wrapped_keys:
            conn.execute(
                "UPDATE shares SET wrapped_key=? WHERE file_id=? AND recipient=?",
                (json.dumps(item.wrapped_key), file_id, item.recipient),
            )
        conn.commit()
        swapped = False
        shutil.rmtree(backup_dir, ignore_errors=True)

    except Exception:
        conn.rollback()
        if swapped and backup_dir is not None and backup_dir.exists():
            active_dir = file_storage_dir(file_id)
            if active_dir.exists():
                shutil.rmtree(active_dir)
            backup_dir.replace(active_dir)
        if staging_dir is not None and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    finally:
        conn.close()

    return {
        "ok": True,
        "storage_format": FILE_STORAGE_FORMAT,
        "total_chunks": total_chunks,
    }

@app.delete("/api/files/{file_id}")
def delete_file(file_id: PathOpaqueId, username: str = Depends(current_user)):
    conn = db()
    require_file_permission(conn, file_id, username, {"owner"})
    row = conn.execute("SELECT id FROM files WHERE id=?", (file_id,)).fetchone()
    conn.execute("DELETE FROM file_requests WHERE file_id=?", (file_id,))
    conn.execute("DELETE FROM shares WHERE file_id=?", (file_id,))
    conn.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()
    if row:
        storage_dir = file_storage_dir(file_id, create_parent=False)
        if storage_dir.exists():
            shutil.rmtree(storage_dir)
    return {"ok": True}


@app.post("/api/share")
def share_file(data: ShareIn, username: str = Depends(current_user)):
    validate_dipp_wrapped_key(data.wrapped_key)
    if (
        data.wrapped_key["sender_id"] != username
        or data.wrapped_key["recipient_id"] != data.recipient
    ):
        raise HTTPException(status_code=400, detail="Wrapped key share tidak terikat ke pengirim/penerima.")
    conn = db()
    require_file_permission(conn, data.file_id, username, {"owner"})
    if not conn.execute("SELECT 1 FROM users WHERE username=?", (data.recipient,)).fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Penerima tidak ditemukan.")
    if data.recipient == username:
        conn.close()
        raise HTTPException(status_code=400, detail="Pemilik sudah punya akses owner.")
    if data.wrapped_key["file_context_id"] != stored_file_context(data.file_id):
        conn.close()
        raise HTTPException(status_code=400, detail="File context wrapped key share tidak cocok.")
    register_dipp_ciphertext(conn, data.wrapped_key, username, data.recipient)
    owner = conn.execute("SELECT owner FROM files WHERE id=?", (data.file_id,)).fetchone()["owner"]
    conn.execute("DELETE FROM shares WHERE file_id=? AND recipient=?", (data.file_id, data.recipient))
    conn.execute(
        "INSERT INTO shares (id, file_id, owner, recipient, wrapped_key, permission, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (new_id(), data.file_id, owner, data.recipient, json.dumps(data.wrapped_key), data.permission, now_iso()),
    )
    conn.execute(
        """
        UPDATE file_requests
        SET status='APPROVED', resolved_at=?
        WHERE file_id=? AND requester=? AND status='PENDING'
        """,
        (now_iso(), data.file_id, data.recipient),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/files/{file_id}/shares/{recipient}")
def revoke_share(file_id: PathOpaqueId, recipient: PathUsername, username: str = Depends(current_user)):
    conn = db()
    require_file_permission(conn, file_id, username, {"owner"})
    owner = conn.execute("SELECT owner FROM files WHERE id=?", (file_id,)).fetchone()["owner"]
    if recipient == owner:
        conn.close()
        raise HTTPException(status_code=400, detail="Akses owner tidak bisa dicabut.")
    conn.execute("DELETE FROM shares WHERE file_id=? AND recipient=?", (file_id, recipient))
    conn.commit()
    conn.close()
    return {"ok": True}


app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")


@app.get("/")
def index():
    return FileResponse(APP_DIR / "static" / "index.html")
