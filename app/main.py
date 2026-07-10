import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ONE_MIND_DATA_DIR", APP_DIR / "data"))
DB_PATH = DATA_DIR / "database" / "one_mind.sqlite3"
STORAGE_DIR = DATA_DIR / "storage"
SECRET_PATH = DATA_DIR / "keys" / "server_secret.bin"

PBKDF2_ITERATIONS = 390_000
SESSION_SECONDS = int(os.environ.get("ONE_MIND_SESSION_SECONDS", "43200"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("ONE_MIND_LOGIN_WINDOW_SECONDS", "600"))
LOGIN_MAX_FAILURES = int(os.environ.get("ONE_MIND_LOGIN_MAX_FAILURES", "8"))
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ONE_MIND_ALLOWED_HOSTS", "*").split(",") if h.strip()]
FAILED_LOGINS: dict[str, list[float]] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def new_id(n: int = 16) -> str:
    return secrets.token_hex(n // 2)

def envelope_path(file_id: str, create_dir: bool = True) -> Path:
    shard = file_id[:2].lower()
    folder = STORAGE_DIR / shard

    if create_dir:
        folder.mkdir(parents=True, exist_ok=True)

    return folder / f"{file_id}.json"


def get_secret() -> bytes:
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(secrets.token_bytes(32))
    return SECRET_PATH.read_bytes()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${b64e(salt)}${b64e(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = b64d(salt_b64)
        expected = b64d(digest_b64)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def sign_token(username: str) -> str:
    nonce = new_id(24)
    payload = {"username": username, "nonce": nonce, "exp": int(time.time()) + SESSION_SECONDS}
    raw = b64e(json.dumps(payload, sort_keys=True).encode("utf-8"))
    sig = hmac.new(get_secret(), raw.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def verify_token(token: str) -> str:
    try:
        raw, sig = token.split(".", 1)
        expected = hmac.new(get_secret(), raw.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError
        payload = json.loads(b64d(raw).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise HTTPException(status_code=401, detail="Sesi sudah kedaluwarsa. Silakan login ulang.")
        return payload["username"]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Token sesi tidak valid.") from exc


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
            public_key TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            filename TEXT NOT NULL,
            envelope_name TEXT NOT NULL,
            encrypted_size INTEGER NOT NULL,
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
        """
    )
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(shares)").fetchall()}
    if "permission" not in columns:
        conn.execute("ALTER TABLE shares ADD COLUMN permission TEXT NOT NULL DEFAULT 'viewer'")
        conn.execute("UPDATE shares SET permission='owner' WHERE recipient=owner")
        conn.commit()
    return conn


def current_user(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login diperlukan.")
    return verify_token(authorization.removeprefix("Bearer ").strip())


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    display_name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=8, max_length=256)
    public_key: dict


class LoginIn(BaseModel):
    username: str
    password: str


class FileUploadIn(BaseModel):
    filename: str = Field(min_length=1, max_length=240)
    envelope: dict
    wrapped_key_for_owner: dict


class ShareIn(BaseModel):
    file_id: str
    recipient: str
    wrapped_key: dict
    permission: Literal["viewer", "editor"] = "viewer"


class WrappedKeyIn(BaseModel):
    recipient: str
    wrapped_key: dict


class FileUpdateIn(BaseModel):
    filename: str = Field(min_length=1, max_length=240)
    envelope: dict
    wrapped_keys: list[WrappedKeyIn] = Field(min_length=1)


class FileRenameIn(BaseModel):
    filename: str = Field(min_length=1, max_length=240)


app = FastAPI(title="ONE_MIND", version="2.0")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
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
    conn = db()
    conn.close()


@app.get("/health")
def health():
    return {"ok": True, "transport": "HTTPS/TLS when run via docker entrypoint"}


@app.post("/api/register")
def register(data: RegisterIn):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO users (username, display_name, password_hash, public_key, created_at) VALUES (?, ?, ?, ?, ?)",
            (data.username, data.display_name, hash_password(data.password), json.dumps(data.public_key), now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Username sudah dipakai.") from exc
    finally:
        conn.close()
    return {"token": sign_token(data.username), "username": data.username}


@app.post("/api/login")
def login(data: LoginIn, request: Request):
    rate_key = check_login_rate(request, data.username)
    conn = db()
    row = conn.execute("SELECT password_hash FROM users WHERE username=?", (data.username,)).fetchone()
    conn.close()
    if not row or not verify_password(data.password, row["password_hash"]):
        record_login_failure(rate_key)
        raise HTTPException(status_code=401, detail="Username atau password salah.")
    clear_login_failures(rate_key)
    return {"token": sign_token(data.username), "username": data.username}


@app.get("/api/me")
def me(username: str = Depends(current_user)):
    conn = db()
    row = conn.execute(
        "SELECT username, display_name, public_key, created_at FROM users WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()
    return dict(row) | {"public_key": json.loads(row["public_key"])}


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
def user_public_key(target_username: str, username: str = Depends(current_user)):
    conn = db()
    row = conn.execute(
        "SELECT username, display_name, public_key FROM users WHERE username=?",
        (target_username,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")
    return {"username": row["username"], "display_name": row["display_name"], "public_key": json.loads(row["public_key"])}


@app.post("/api/files")
def upload_file(data: FileUploadIn, username: str = Depends(current_user)):
    file_id = new_id()
    envelope_name = f"{file_id}.json"
    envelope_bytes = json.dumps(
    data.envelope,
    ensure_ascii=False,
    separators=(",", ":")
    ).encode("utf-8")
    envelope_path(file_id).write_bytes(envelope_bytes)

    conn = db()
    conn.execute(
        "INSERT INTO files (id, owner, filename, envelope_name, encrypted_size, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (file_id, username, data.filename, envelope_name, len(envelope_bytes), now_iso()),
    )
    conn.execute(
        "INSERT INTO shares (id, file_id, owner, recipient, wrapped_key, permission, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (new_id(), file_id, username, username, json.dumps(data.wrapped_key_for_owner), "owner", now_iso()),
    )
    conn.commit()
    conn.close()
    return {"file_id": file_id}


@app.get("/api/files")
def list_files(username: str = Depends(current_user)):
    conn = db()
    rows = conn.execute(
        """
        SELECT f.id, f.owner, f.filename, f.encrypted_size, f.created_at, s.permission
        FROM files f
        JOIN shares s ON s.file_id = f.id
        WHERE s.recipient = ?
        GROUP BY f.id
        ORDER BY f.created_at DESC
        """,
        (username,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/files/{file_id}")
def download_file(file_id: str, username: str = Depends(current_user)):
    conn = db()
    row = conn.execute(
        """
        SELECT f.id, f.owner, f.filename, f.envelope_name, s.wrapped_key, s.permission
        FROM files f
        JOIN shares s ON s.file_id = f.id
        WHERE f.id = ? AND s.recipient = ?
        """,
        (file_id, username),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="File tidak ditemukan atau belum dibagikan ke akun ini.")
    env_path = envelope_path(row["id"], create_dir=False)
    return {
        "id": row["id"],
        "owner": row["owner"],
        "filename": row["filename"],
        "permission": row["permission"],
        "envelope": json.loads(envelope_path.read_text()),
        "wrapped_key": json.loads(row["wrapped_key"]),
    }


@app.get("/api/files/{file_id}/access")
def file_access(file_id: str, username: str = Depends(current_user)):
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
def rename_file(file_id: str, data: FileRenameIn, username: str = Depends(current_user)):
    conn = db()
    require_file_permission(conn, file_id, username, {"owner", "editor"})
    conn.execute("UPDATE files SET filename=? WHERE id=?", (data.filename, file_id))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.put("/api/files/{file_id}")
def update_file(file_id: str, data: FileUpdateIn, username: str = Depends(current_user)):
    conn = db()
    require_file_permission(conn, file_id, username, {"owner", "editor"})
    expected_recipients = access_usernames(conn, file_id)
    submitted_recipients = {item.recipient for item in data.wrapped_keys}
    if submitted_recipients != expected_recipients:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Wrapped key harus dibuat ulang untuk semua user yang masih punya akses.",
        )
    row = conn.execute("SELECT id FROM files WHERE id=?", (file_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="File tidak ditemukan.")
    envelope_bytes = json.dumps(
        data.envelope,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")
    envelope_path(file_id).write_bytes(envelope_bytes)
    conn.execute(
        "UPDATE files SET filename=?, encrypted_size=? WHERE id=?",
        (data.filename, len(envelope_bytes), file_id),
    )
    for item in data.wrapped_keys:
        conn.execute(
            "UPDATE shares SET wrapped_key=? WHERE file_id=? AND recipient=?",
            (json.dumps(item.wrapped_key), file_id, item.recipient),
        )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/files/{file_id}")
def delete_file(file_id: str, username: str = Depends(current_user)):
    conn = db()
    require_file_permission(conn, file_id, username, {"owner"})
    row = conn.execute("SELECT envelope_name FROM files WHERE id=?", (file_id,)).fetchone()
    conn.execute("DELETE FROM shares WHERE file_id=?", (file_id,))
    conn.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()
    if row:
        env_path = envelope_path(file_id, create_dir=False)
        if env_path.exists():
            env_path.unlink()
    return {"ok": True}


@app.post("/api/share")
def share_file(data: ShareIn, username: str = Depends(current_user)):
    conn = db()
    require_file_permission(conn, data.file_id, username, {"owner"})
    if not conn.execute("SELECT 1 FROM users WHERE username=?", (data.recipient,)).fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Penerima tidak ditemukan.")
    if data.recipient == username:
        conn.close()
        raise HTTPException(status_code=400, detail="Pemilik sudah punya akses owner.")
    owner = conn.execute("SELECT owner FROM files WHERE id=?", (data.file_id,)).fetchone()["owner"]
    conn.execute("DELETE FROM shares WHERE file_id=? AND recipient=?", (data.file_id, data.recipient))
    conn.execute(
        "INSERT INTO shares (id, file_id, owner, recipient, wrapped_key, permission, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (new_id(), data.file_id, owner, data.recipient, json.dumps(data.wrapped_key), data.permission, now_iso()),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/files/{file_id}/shares/{recipient}")
def revoke_share(file_id: str, recipient: str, username: str = Depends(current_user)):
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
