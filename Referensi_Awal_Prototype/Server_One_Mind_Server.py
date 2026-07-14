"""
Server_One_Mind_Server.py
=========================
Server SUNGGUHAN untuk One_Mind: socket TCP + TLS standar (bukan lagi
simulasi satu proses). Jalankan file ini di komputer yang berperan
sebagai server:

    python Server_One_Mind_Server.py --host 0.0.0.0 --port 5555

Lapis 1 (transport) sekarang pakai TLS -- mekanisme umum di socket,
sesuai permintaan. Sertifikat TLS (self-signed) dibuat otomatis sekali
di ~/.one_mind/server/server.crt -- file inilah yang perlu dibagikan ke
setiap client (lewat jalur apa saja: USB, chat, dsb) supaya mereka bisa
connect dengan trust yang benar (client memverifikasi PERSIS sertifikat
ini, bukan asal percaya).

Lapis 2 (end-to-end per file) TIDAK berubah dari desain sebelumnya:
- Isi file "plain" vs "terenkripsi" tetap ditentukan pemilik file
  (pakai Enkripsi_One_Mind sebelum upload kalau mau dienkripsi).
- Pertukaran kunci AES antar pengguna tetap lewat DIPP-KEM
  (Key_Generator_and_Enkriptor_DIPP_One_Mind), server hanya menyimpan/
  meneruskan blob kunci terbungkus itu apa adanya.
- Public key DIPP tiap pengguna tetap disetor saat registrasi (dipakai
  nanti utk membungkus kunci ke pengguna itu).

Karena transport request/response registrasi & login kini otomatis
terlindungi oleh TLS, kredensial (username/password/sertifikat) boleh
dikirim langsung dalam respons TLS -- tidak perlu lagi double-enkripsi
manual seperti versi simulator sebelumnya.
"""

import argparse
import hashlib
import hmac
import json
import secrets
import socket
import sqlite3
import ssl
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


SERVER_DIR = Path.home() / ".one_mind" / "server"
DB_PATH = SERVER_DIR / "onemind.sqlite3"
STORAGE_DIR = SERVER_DIR / "storage"
SECRET_PATH = SERVER_DIR / "server_secret.bin"     # kunci HMAC utk tanda tangan sertifikat akun
TLS_CERT_PATH = SERVER_DIR / "server.crt"
TLS_KEY_PATH = SERVER_DIR / "server.key"


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(n=10) -> str:
    return uuid.uuid4().hex[:n]


def slugify(text: str) -> str:
    keep = [c.lower() if c.isalnum() else "_" for c in text.strip()]
    slug = "".join(keep).strip("_") or "pengguna"
    return slug[:20]


def b64e(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    import base64
    return base64.b64decode(text.encode("ascii"))


# ──────────────────────────────────────────────
# TLS: bikin sertifikat self-signed sekali kalau belum ada
# ──────────────────────────────────────────────

def ensure_tls_cert():
    SERVER_DIR.mkdir(parents=True, exist_ok=True)
    if TLS_CERT_PATH.exists() and TLS_KEY_PATH.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Server_One_Mind")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, crypto_hashes.SHA256())
    )
    TLS_KEY_PATH.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    TLS_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ──────────────────────────────────────────────
# Framing pesan: 4-byte length prefix + JSON UTF-8
# ──────────────────────────────────────────────

def send_msg(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi terputus.")
        buf += chunk
    return buf


def recv_msg(sock):
    length = int.from_bytes(recv_exact(sock, 4), "big")
    if length > 200 * 1024 * 1024:
        raise ValueError("Pesan terlalu besar.")
    return json.loads(recv_exact(sock, length).decode("utf-8"))


# ──────────────────────────────────────────────
# ServerStore: logika bisnis (identik dengan versi simulator)
# ──────────────────────────────────────────────

class ServerStore:
    """Sama persis API publiknya dengan versi sebelumnya (JSON) -- hanya
    penyimpanannya diganti ke SQLite. ClientSession, client, dan 2 app
    lain tidak perlu tahu/berubah sama sekali."""

    def __init__(self):
        SERVER_DIR.mkdir(parents=True, exist_ok=True)
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        if not SECRET_PATH.exists():
            SECRET_PATH.write_bytes(secrets.token_bytes(32))
        self.server_secret = SECRET_PATH.read_bytes()

        self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                cert_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                dipp_public_key TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                kind TEXT NOT NULL,
                message TEXT NOT NULL,
                data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                owner TEXT NOT NULL,
                filename TEXT NOT NULL,
                folder TEXT NOT NULL,
                visibility TEXT NOT NULL,
                encrypted INTEGER NOT NULL,
                edit_allowed INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                size INTEGER NOT NULL,
                storage_name TEXT,
                FOREIGN KEY (owner) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS key_requests (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                requester TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                wrap_storage_name TEXT,
                FOREIGN KEY (file_id) REFERENCES files(id)
            );

            CREATE TABLE IF NOT EXISTS edit_requests (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                requester TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner);
            CREATE INDEX IF NOT EXISTS idx_notifications_username ON notifications(username);
            CREATE INDEX IF NOT EXISTS idx_key_requests_file ON key_requests(file_id);
            CREATE INDEX IF NOT EXISTS idx_edit_requests_file ON edit_requests(file_id);
            CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
            """
        )
        self.conn.commit()

    # -- audit log -----------------------------------------------------------

    def log(self, actor, action, detail=""):
        self.conn.execute(
            "INSERT INTO audit_log (time, actor, action, detail) VALUES (?, ?, ?, ?)",
            (now_iso(), actor, action, detail),
        )
        self.conn.commit()

    # -- registrasi & sertifikat ----------------------------------------------

    def register_user(self, display_name, dipp_public_key):
        username = slugify(display_name) + "_" + new_id(4)
        while self.conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            username = slugify(display_name) + "_" + new_id(4)
        password = secrets.token_urlsafe(12)
        cert_id = new_id(16)
        pubkey_fingerprint = hashlib.sha256(json.dumps(dipp_public_key, sort_keys=True).encode("utf-8")).hexdigest()
        cert_core = {"cert_id": cert_id, "username": username, "display_name": display_name,
                     "issued_at": now_iso(), "pubkey_fingerprint": pubkey_fingerprint}
        signature = hmac.new(self.server_secret, json.dumps(cert_core, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
        certificate = dict(cert_core)
        certificate["signature"] = signature

        self.conn.execute(
            "INSERT INTO users (username, cert_id, display_name, password_hash, dipp_public_key, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, cert_id, display_name, hashlib.sha256(password.encode("utf-8")).hexdigest(),
             json.dumps(dipp_public_key), now_iso()),
        )
        self.conn.commit()
        self.log(username, "register", f"Akun '{display_name}' terdaftar.")
        return username, password, certificate

    def verify_certificate(self, certificate):
        cert_core = {k: v for k, v in certificate.items() if k != "signature"}
        expected_sig = hmac.new(self.server_secret, json.dumps(cert_core, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, certificate.get("signature", "")):
            raise ValueError("Sertifikat tidak valid (tanda tangan tidak cocok).")
        username = certificate.get("username")
        row = self.conn.execute("SELECT cert_id FROM users WHERE username=?", (username,)).fetchone()
        if not row or row["cert_id"] != certificate.get("cert_id"):
            raise ValueError("Sertifikat tidak dikenali atau sudah tidak berlaku.")
        return username

    def verify_password(self, username, password):
        row = self.conn.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return False
        return hmac.compare_digest(row["password_hash"], hashlib.sha256(password.encode("utf-8")).hexdigest())

    def update_public_key(self, username, new_public_key, password):
        if not self.verify_password(username, password):
            raise ValueError("Password salah, pembaruan public key dibatalkan.")
        self.conn.execute("UPDATE users SET dipp_public_key=? WHERE username=?", (json.dumps(new_public_key), username))
        self.conn.commit()
        self.log(username, "update_public_key", "Public key DIPP diperbarui.")

    def rename_display_name(self, username, new_name):
        self.conn.execute("UPDATE users SET display_name=? WHERE username=?", (new_name, username))
        self.conn.commit()
        self.log(username, "rename", f"Nama tampilan diubah menjadi '{new_name}'.")

    def get_user(self, username):
        row = self.conn.execute(
            "SELECT username, cert_id, display_name, password_hash, dipp_public_key, created_at "
            "FROM users WHERE username=?", (username,),
        ).fetchone()
        if not row:
            raise KeyError(f"User '{username}' tidak ditemukan.")
        return {
            "cert_id": row["cert_id"], "display_name": row["display_name"],
            "password_hash": row["password_hash"], "dipp_public_key": json.loads(row["dipp_public_key"]),
            "created_at": row["created_at"],
        }

    def list_other_users(self, exclude):
        rows = self.conn.execute("SELECT username, display_name FROM users WHERE username != ?", (exclude,)).fetchall()
        return [{"username": r["username"], "display_name": r["display_name"]} for r in rows]

    def add_notification(self, username, kind, message, data=None):
        self.conn.execute(
            "INSERT INTO notifications (id, username, kind, message, data, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_id(8), username, kind, message, json.dumps(data or {}), "baru", now_iso()),
        )
        self.conn.commit()

    def notifications(self, username):
        rows = self.conn.execute(
            "SELECT id, kind, message, data, status, created_at FROM notifications WHERE username=? ORDER BY created_at",
            (username,),
        ).fetchall()
        return [
            {"id": r["id"], "kind": r["kind"], "message": r["message"], "data": json.loads(r["data"]),
             "status": r["status"], "created_at": r["created_at"]}
            for r in rows
        ]

    # -- files -----------------------------------------------------------------

    def create_folder(self, owner, folder_path):
        file_id = new_id()
        name = folder_path.strip("/").split("/")[-1] or folder_path
        self.conn.execute(
            "INSERT INTO files (id, kind, owner, filename, folder, visibility, encrypted, edit_allowed, "
            "uploaded_at, size, storage_name) VALUES (?, 'folder', ?, ?, ?, 'private', 0, 0, ?, 0, NULL)",
            (file_id, owner, name, folder_path, now_iso()),
        )
        self.conn.commit()
        self.log(owner, "create_folder", folder_path)

    def upload_file(self, owner, filename, folder, visibility, encrypted, raw_bytes, edit_allowed=False):
        file_id = new_id()
        storage_name = f"{file_id}.bin"
        (STORAGE_DIR / storage_name).write_bytes(raw_bytes)
        real_edit_allowed = bool(edit_allowed) if (visibility == "public" and not encrypted) else False
        self.conn.execute(
            "INSERT INTO files (id, kind, owner, filename, folder, visibility, encrypted, edit_allowed, "
            "uploaded_at, size, storage_name) VALUES (?, 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (file_id, owner, filename, folder, visibility, int(bool(encrypted)), int(real_edit_allowed),
             now_iso(), len(raw_bytes), storage_name),
        )
        self.conn.commit()
        self.log(owner, "upload", f"{filename} ({visibility}, {'terenkripsi' if encrypted else 'plain'})")
        return file_id

    def replace_file_content(self, file_id, raw_bytes, actor):
        entry = self.get_item(file_id)
        if not self.can_edit(file_id, actor):
            raise PermissionError("Kamu tidak punya izin mengedit file ini.")
        (STORAGE_DIR / entry["storage_name"]).write_bytes(raw_bytes)
        self.conn.execute("UPDATE files SET size=?, uploaded_at=? WHERE id=?", (len(raw_bytes), now_iso(), file_id))
        self.conn.commit()
        self.log(actor, "edit", f"Mengganti isi file {entry['filename']} (id={file_id})")

    def delete_file(self, file_id, actor):
        row = self.conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            raise ValueError("File tidak ditemukan.")
        if row["owner"] != actor:
            raise PermissionError("Hanya pemilik yang boleh menghapus file ini.")
        if row["storage_name"]:
            path = STORAGE_DIR / row["storage_name"]
            if path.exists():
                path.unlink()
        self.conn.execute("DELETE FROM key_requests WHERE file_id=?", (file_id,))
        self.conn.execute("DELETE FROM edit_requests WHERE file_id=?", (file_id,))
        self.conn.execute("DELETE FROM files WHERE id=?", (file_id,))
        self.conn.commit()
        self.log(actor, "delete", f"{row['filename']} (id={file_id})")

    def _row_to_item(self, row) -> dict:
        item = {
            "id": row["id"], "kind": row["kind"], "owner": row["owner"], "filename": row["filename"],
            "folder": row["folder"], "visibility": row["visibility"], "encrypted": bool(row["encrypted"]),
            "edit_allowed": bool(row["edit_allowed"]), "uploaded_at": row["uploaded_at"],
            "size": row["size"], "storage_name": row["storage_name"],
        }
        item["key_requests"] = [
            {"id": r["id"], "requester": r["requester"], "status": r["status"],
             "created_at": r["created_at"], "wrap_storage_name": r["wrap_storage_name"]}
            for r in self.conn.execute(
                "SELECT id, requester, status, created_at, wrap_storage_name FROM key_requests "
                "WHERE file_id=? ORDER BY created_at", (row["id"],),
            ).fetchall()
        ]
        item["edit_requests"] = [
            {"id": r["id"], "requester": r["requester"], "status": r["status"], "created_at": r["created_at"]}
            for r in self.conn.execute(
                "SELECT id, requester, status, created_at FROM edit_requests WHERE file_id=? ORDER BY created_at",
                (row["id"],),
            ).fetchall()
        ]
        return item

    def list_own_items(self, owner):
        rows = self.conn.execute("SELECT * FROM files WHERE owner=?", (owner,)).fetchall()
        return [self._row_to_item(r) for r in rows]

    def list_public_items(self, owner):
        rows = self.conn.execute(
            "SELECT * FROM files WHERE owner=? AND visibility='public' AND kind='file'", (owner,),
        ).fetchall()
        return [self._row_to_item(r) for r in rows]

    def get_item(self, file_id):
        row = self.conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            raise KeyError(f"File '{file_id}' tidak ditemukan.")
        return self._row_to_item(row)

    def read_file_bytes(self, file_id, requester):
        entry = self.get_item(file_id)
        if entry["visibility"] == "private" and entry["owner"] != requester:
            raise PermissionError("File privat, hanya pemilik yang boleh mengunduh.")
        return (STORAGE_DIR / entry["storage_name"]).read_bytes()

    # -- alur permintaan kunci --------------------------------------------------

    def request_key(self, file_id, requester):
        entry = self.get_item(file_id)
        if entry["visibility"] != "public" or not entry["encrypted"]:
            raise ValueError("Permintaan kunci hanya berlaku untuk file publik yang terenkripsi.")
        request_id = new_id(8)
        self.conn.execute(
            "INSERT INTO key_requests (id, file_id, requester, status, created_at, wrap_storage_name) "
            "VALUES (?, ?, ?, 'diminta', ?, NULL)",
            (request_id, file_id, requester, now_iso()),
        )
        self.conn.commit()
        self.add_notification(entry["owner"], "key_request", f"{requester} meminta kunci untuk file '{entry['filename']}'.",
                               {"file_id": file_id, "request_id": request_id})
        self.log(requester, "request_key", f"file_id={file_id}")

    def _get_key_request(self, file_id, request_id):
        row = self.conn.execute(
            "SELECT * FROM key_requests WHERE file_id=? AND id=?", (file_id, request_id),
        ).fetchone()
        if not row:
            raise ValueError("Permintaan kunci tidak ditemukan.")
        return row

    def grant_key_request(self, file_id, request_id, owner):
        entry = self.get_item(file_id)
        if entry["owner"] != owner:
            raise PermissionError("Hanya pemilik yang boleh menyetujui permintaan kunci.")
        req = self._get_key_request(file_id, request_id)
        self.conn.execute("UPDATE key_requests SET status='disetujui' WHERE id=?", (request_id,))
        self.conn.commit()
        self.add_notification(req["requester"], "key_granted",
                               f"Permintaan kuncimu untuk '{entry['filename']}' disetujui. Menunggu pemilik mengirim kunci.",
                               {"file_id": file_id, "request_id": request_id})
        self.log(owner, "grant_key_request", f"file_id={file_id} request_id={request_id}")

    def deliver_key(self, file_id, request_id, owner, wrap_bytes):
        entry = self.get_item(file_id)
        if entry["owner"] != owner:
            raise PermissionError("Hanya pemilik yang boleh mengirim kunci.")
        req = self._get_key_request(file_id, request_id)
        storage_name = f"wrap_{file_id}_{request_id}.dwrap.json"
        (STORAGE_DIR / storage_name).write_bytes(wrap_bytes)
        self.conn.execute("UPDATE key_requests SET status='terkirim', wrap_storage_name=? WHERE id=?", (storage_name, request_id))
        self.conn.commit()
        self.add_notification(req["requester"], "key_delivered", f"Kunci untuk '{entry['filename']}' sudah tersedia untuk diunduh.",
                               {"file_id": file_id, "request_id": request_id})
        self.log(owner, "deliver_key", f"file_id={file_id} request_id={request_id}")

    def download_delivered_key(self, file_id, request_id, requester):
        req = self._get_key_request(file_id, request_id)
        if req["requester"] != requester:
            raise PermissionError("Ini bukan paket kunci milikmu.")
        if req["status"] != "terkirim":
            raise ValueError("Kunci belum dikirim oleh pemilik.")
        return (STORAGE_DIR / req["wrap_storage_name"]).read_bytes()

    # -- alur permintaan edit -----------------------------------------------------

    def request_edit(self, file_id, requester):
        entry = self.get_item(file_id)
        if entry["visibility"] != "public" or entry["encrypted"]:
            raise ValueError("Permintaan edit hanya untuk file publik yang tidak terenkripsi.")
        if entry["edit_allowed"]:
            raise ValueError("File ini sudah bebas diedit, tidak perlu meminta izin.")
        request_id = new_id(8)
        self.conn.execute(
            "INSERT INTO edit_requests (id, file_id, requester, status, created_at) VALUES (?, ?, ?, 'diminta', ?)",
            (request_id, file_id, requester, now_iso()),
        )
        self.conn.commit()
        self.add_notification(entry["owner"], "edit_request", f"{requester} meminta izin edit untuk file '{entry['filename']}'.",
                               {"file_id": file_id, "request_id": request_id})
        self.log(requester, "request_edit", f"file_id={file_id}")

    def decide_edit_request(self, file_id, request_id, owner, approve):
        entry = self.get_item(file_id)
        if entry["owner"] != owner:
            raise PermissionError("Hanya pemilik yang boleh memutuskan permintaan edit.")
        row = self.conn.execute(
            "SELECT * FROM edit_requests WHERE file_id=? AND id=?", (file_id, request_id),
        ).fetchone()
        if not row:
            raise ValueError("Permintaan edit tidak ditemukan.")
        new_status = "disetujui" if approve else "ditolak"
        self.conn.execute("UPDATE edit_requests SET status=? WHERE id=?", (new_status, request_id))
        self.conn.commit()
        self.add_notification(row["requester"], "edit_decision",
                               f"Permintaan editmu untuk '{entry['filename']}' {'disetujui' if approve else 'ditolak'}.",
                               {"file_id": file_id, "request_id": request_id})
        self.log(owner, "decide_edit_request", f"file_id={file_id} approve={approve}")

    def can_edit(self, file_id, requester):
        entry = self.get_item(file_id)
        if entry["owner"] == requester:
            return True
        if entry["visibility"] != "public" or entry["encrypted"]:
            return False
        if entry["edit_allowed"]:
            return True
        return any(r["requester"] == requester and r["status"] == "disetujui" for r in entry["edit_requests"])

    def audit_log_for(self, actor):
        rows = self.conn.execute(
            "SELECT time, actor, action, detail FROM audit_log WHERE actor=? ORDER BY id", (actor,),
        ).fetchall()
        return [{"time": r["time"], "actor": r["actor"], "action": r["action"], "detail": r["detail"]} for r in rows]


# ──────────────────────────────────────────────
# Sesi per koneksi TCP (satu thread per client)
# ──────────────────────────────────────────────

class ClientSession(threading.Thread):
    def __init__(self, tls_sock, addr, store: ServerStore, lock: threading.Lock):
        super().__init__(daemon=True)
        self.sock, self.addr, self.store, self.lock = tls_sock, addr, store, lock
        self.username = None

    def run(self):
        try:
            while True:
                try:
                    request = recv_msg(self.sock)
                except (ConnectionError, OSError, ValueError, json.JSONDecodeError):
                    break
                action = request.get("action")
                params = request.get("params", {}) or {}
                try:
                    with self.lock:
                        result = self.dispatch(action, params)
                    response = {"ok": True, "result": result}
                except Exception as exc:
                    response = {"ok": False, "error": str(exc)}
                try:
                    send_msg(self.sock, response)
                except OSError:
                    break
        finally:
            try:
                self.sock.close()
            except OSError:
                pass
            print(f"[-] Klien {self.addr} terputus.")

    def dispatch(self, action, p):
        s = self.store

        if action == "register":
            username, password, certificate = s.register_user(p["display_name"], p["public_key"])
            return {"username": username, "password": password, "certificate": certificate}

        if action == "login":
            username = s.verify_certificate(p["certificate"])
            self.username = username
            s.log(username, "login", f"Login dari {self.addr[0]}")
            return {"username": username, "display_name": s.get_user(username)["display_name"]}

        if action == "logout":
            if self.username:
                s.log(self.username, "logout", "")
            self.username = None
            return {}

        if not self.username:
            raise PermissionError("Belum login.")
        me = self.username

        if action == "list_own_items":
            return s.list_own_items(me)
        if action == "list_public_items":
            return s.list_public_items(p["owner"])
        if action == "list_other_users":
            return s.list_other_users(me)
        if action == "get_user_public_key":
            return s.get_user(p["username"])["dipp_public_key"]
        if action == "create_folder":
            s.create_folder(me, p["folder_path"]); return {}
        if action == "upload_file":
            return {"file_id": s.upload_file(me, p["filename"], p["folder"], p["visibility"],
                                              p["encrypted"], b64d(p["data_b64"]), p.get("edit_allowed", False))}
        if action == "download_file":
            item = s.get_item(p["file_id"])
            data = s.read_file_bytes(p["file_id"], me)
            return {"filename": item["filename"], "encrypted": item["encrypted"], "data_b64": b64e(data)}
        if action == "delete_file":
            s.delete_file(p["file_id"], me); return {}
        if action == "replace_file_content":
            s.replace_file_content(p["file_id"], b64d(p["data_b64"]), me); return {}
        if action == "request_key":
            s.request_key(p["file_id"], me); return {}
        if action == "grant_key_request":
            s.grant_key_request(p["file_id"], p["request_id"], me); return {}
        if action == "deliver_key":
            s.deliver_key(p["file_id"], p["request_id"], me, b64d(p["wrap_b64"])); return {}
        if action == "download_delivered_key":
            data = s.download_delivered_key(p["file_id"], p["request_id"], me)
            return {"data_b64": b64e(data)}
        if action == "request_edit":
            s.request_edit(p["file_id"], me); return {}
        if action == "decide_edit_request":
            s.decide_edit_request(p["file_id"], p["request_id"], me, p["approve"]); return {}
        if action == "can_edit":
            return {"can_edit": s.can_edit(p["file_id"], me)}
        if action == "notifications":
            return s.notifications(me)
        if action == "rename_display_name":
            s.rename_display_name(me, p["new_name"]); return {}
        if action == "update_public_key":
            s.update_public_key(me, p["new_public_key"], p["password"]); return {}
        if action == "audit_log_mine":
            return s.audit_log_for(me)

        raise ValueError(f"Aksi tidak dikenal: {action}")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def run_server(host="0.0.0.0", port=5555):
    ensure_tls_cert()
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=str(TLS_CERT_PATH), keyfile=str(TLS_KEY_PATH))

    store = ServerStore()
    lock = threading.Lock()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(50)

    print("=" * 60)
    print("Server_One_Mind aktif.")
    print(f"  Alamat  : {host}:{port}")
    print(f"  Sertifikat TLS (bagikan ke setiap client): {TLS_CERT_PATH}")
    print(f"  Data server tersimpan di                 : {SERVER_DIR}")
    print("=" * 60)

    try:
        while True:
            raw_conn, addr = listener.accept()
            try:
                tls_conn = ssl_context.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as exc:
                print(f"[!] Gagal TLS handshake dengan {addr}: {exc}")
                raw_conn.close()
                continue
            print(f"[+] Klien terhubung dari {addr}")
            ClientSession(tls_conn, addr, store, lock).start()
    except KeyboardInterrupt:
        print("\nServer dihentikan.")
    finally:
        listener.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Server_One_Mind - server socket TLS")
    parser.add_argument("--host", default="0.0.0.0", help="Alamat untuk listen (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5555, help="Port untuk listen (default 5555)")
    args = parser.parse_args()
    run_server(args.host, args.port)
