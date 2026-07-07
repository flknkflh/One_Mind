"""
Enkripsi_One_Mind
==================
Aplikasi enkripsi/dekripsi simetrik (AES-256-GCM) untuk ekosistem One_Mind.

Perubahan besar dari versi sebelumnya (app2cocok.py):

1. Key Manager lokal (keystore terenkripsi di ~/.one_mind/keystore.enc,
   dilindungi master password). Kunci-kunci hasil enkripsi TIDAK lagi
   tercecer sebagai file lepas -- semua tersimpan & bisa dipilih dari daftar.
2. Setiap enkripsi memakai kunci acak baru (bukan diturunkan dari
   password), sesuai alur One_Mind: kunci itulah yang nanti dibungkus
   memakai Key_Generator_and_Enkriptor_DIPP_One_Mind (asimetrik) saat mau
   dibagikan ke pengguna lain.
3. File data terenkripsi (.bin) sekarang jadi paket mandiri berisi
   nonce + AAD + ciphertext (semuanya publik/tidak rahasia) -- aman untuk
   diupload ke server. Kunci rahasia betul-betul terpisah, baik tersimpan
   di Key Manager maupun diekspor sebagai file kunci portable (.key.txt)
   untuk keperluan pertukaran lewat app DIPP.
4. decrypt_with_password (belum lengkap di versi lama) dihapus --
   digantikan alur pilih-kunci-dari-manager / impor-file-kunci.
"""

import base64
import json
import os
import secrets
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from tkinter import (
    BOTH, END, LEFT, RIGHT, VERTICAL, W, X, Y,
    filedialog, messagebox, simpledialog,
)
import tkinter as tk
from tkinter import ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


APP_VERSION = 3
KDF_ITERATIONS = 600_000
ALGORITHM = "AES-256-GCM"

ONE_MIND_DIR = Path.home() / ".one_mind"
KEYSTORE_PATH = ONE_MIND_DIR / "keystore.enc"


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_filename(name: str) -> str:
    clean = Path(name).name.strip()
    return clean or "decrypted_message.txt"


def derive_master_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    )
    return kdf.derive(password.encode("utf-8"))


# ──────────────────────────────────────────────
# Core AES-256-GCM envelope (the actual "Enkripsi_One_Mind" engine)
# ──────────────────────────────────────────────

def encrypt_payload(payload: bytes, filename: str, payload_type: str, key: bytes) -> dict:
    """Encrypt payload with a given 256-bit key. Returns a self-describing
    envelope dict. Nothing in this envelope is secret except that it must
    be paired with `key` to be opened."""
    nonce = os.urandom(12)
    aad = json.dumps(
        {
            "version": APP_VERSION,
            "algorithm": ALGORITHM,
            "filename": filename,
            "payload_type": payload_type,
        },
        sort_keys=True,
    ).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
    return {
        "version": APP_VERSION,
        "algorithm": ALGORITHM,
        "filename": filename,
        "payload_type": payload_type,
        "nonce": b64e(nonce),
        "aad": b64e(aad),
        "ciphertext": b64e(ciphertext),
    }


def write_envelope(envelope: dict, output_path: Path) -> Path:
    data_file = output_path.with_suffix(".bin")
    data_file.write_text(json.dumps(envelope, indent=2))
    return data_file


def decrypt_envelope(envelope: dict, key: bytes) -> bytes:
    nonce = b64d(envelope["nonce"])
    aad = b64d(envelope["aad"])
    ciphertext = b64d(envelope["ciphertext"])
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("Data terenkripsi rusak, atau kunci yang dipilih tidak cocok.") from exc


# ──────────────────────────────────────────────
# Key Manager (encrypted local keystore)
# ──────────────────────────────────────────────

class KeyManager:
    """Keeps AES keys out of loose files. Backed by a single encrypted
    JSON blob on disk, unlocked with a master password held only in
    memory for the life of the app session."""

    def __init__(self):
        self.master_key: bytes | None = None
        self.salt: bytes | None = None
        self.iterations = KDF_ITERATIONS
        self.keys: list[dict] = []  # {id, label, key_b64, algorithm, created, note}

    # -- lifecycle -----------------------------------------------------

    def exists_on_disk(self) -> bool:
        return KEYSTORE_PATH.exists()

    def create_new(self, password: str):
        ONE_MIND_DIR.mkdir(parents=True, exist_ok=True)
        self.salt = os.urandom(16)
        self.master_key = derive_master_key(password, self.salt, self.iterations)
        self.keys = []
        self._save()

    def unlock(self, password: str):
        raw = json.loads(KEYSTORE_PATH.read_text())
        salt = b64d(raw["kdf_salt"])
        iterations = raw["kdf_iterations"]
        candidate_key = derive_master_key(password, salt, iterations)
        nonce = b64d(raw["nonce"])
        ciphertext = b64d(raw["ciphertext"])
        try:
            plaintext = AESGCM(candidate_key).decrypt(nonce, ciphertext, b"one_mind_keystore")
        except InvalidTag as exc:
            raise ValueError("Master password salah.") from exc
        self.salt = salt
        self.iterations = iterations
        self.master_key = candidate_key
        self.keys = json.loads(plaintext.decode("utf-8"))["keys"]

    def change_password(self, new_password: str):
        self.salt = os.urandom(16)
        self.iterations = KDF_ITERATIONS
        self.master_key = derive_master_key(new_password, self.salt, self.iterations)
        self._save()

    def _save(self):
        payload = json.dumps({"keys": self.keys}).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.master_key).encrypt(nonce, payload, b"one_mind_keystore")
        raw = {
            "kdf_salt": b64e(self.salt),
            "kdf_iterations": self.iterations,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
        }
        KEYSTORE_PATH.write_text(json.dumps(raw, indent=2))

    # -- key operations --------------------------------------------------

    def add_key(self, key: bytes, label: str, note: str = "") -> dict:
        entry = {
            "id": uuid.uuid4().hex[:12],
            "label": label or "Kunci tanpa nama",
            "key_b64": b64e(key),
            "algorithm": ALGORITHM,
            "created": now_iso(),
            "note": note,
        }
        self.keys.append(entry)
        self._save()
        return entry

    def rename_key(self, key_id: str, new_label: str):
        for k in self.keys:
            if k["id"] == key_id:
                k["label"] = new_label
                self._save()
                return
        raise ValueError("Kunci tidak ditemukan.")

    def delete_key(self, key_id: str):
        before = len(self.keys)
        self.keys = [k for k in self.keys if k["id"] != key_id]
        if len(self.keys) == before:
            raise ValueError("Kunci tidak ditemukan.")
        self._save()

    def get_key_bytes(self, key_id: str) -> bytes:
        for k in self.keys:
            if k["id"] == key_id:
                return b64d(k["key_b64"])
        raise ValueError("Kunci tidak ditemukan.")

    def import_key_file(self, path: Path, label: str | None = None) -> dict:
        raw = json.loads(Path(path).read_text())
        key = b64d(raw["key_b64"])
        entry_label = label or raw.get("label") or f"Impor: {Path(path).stem}"
        return self.add_key(key, entry_label, note=f"Diimpor dari {Path(path).name}")

    def export_key_file(self, key_id: str, output_path: Path) -> Path:
        entry = next((k for k in self.keys if k["id"] == key_id), None)
        if entry is None:
            raise ValueError("Kunci tidak ditemukan.")
        portable = {
            "version": APP_VERSION,
            "algorithm": entry["algorithm"],
            "label": entry["label"],
            "key_b64": entry["key_b64"],
        }
        out = output_path.with_suffix(".key.txt")
        out.write_text(json.dumps(portable, indent=2))
        return out


# ──────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────

class EnkripsiOneMindApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Enkripsi_One_Mind — AES-256-GCM")
        self.geometry("880x600")
        self.minsize(780, 520)
        self.configure(bg="#f5f7fb")

        self.key_manager = KeyManager()

        self.selected_file = tk.StringVar()
        self.new_key_label = tk.StringVar()
        self.encrypt_key_choice = tk.StringVar(value="new")
        self.encrypt_existing_key_id = tk.StringVar()
        self.export_key_var = tk.BooleanVar(value=False)

        self.decrypt_data_var = tk.StringVar()
        self.decrypt_key_source = tk.StringVar(value="manager")
        self.decrypt_existing_key_id = tk.StringVar()
        self.decrypt_key_file_var = tk.StringVar()

        self.output_dir = tk.StringVar(value=str(Path.home() / "Downloads"))
        self.status = tk.StringVar(value="Selamat datang di Enkripsi_One_Mind.")

        self._build_styles()
        self.withdraw()
        if self._unlock_keystore():
            self.deiconify()
            self.show_home()
        else:
            self.destroy()

    # ── Keystore unlock flow ──────────────────

    def _unlock_keystore(self) -> bool:
        if not self.key_manager.exists_on_disk():
            messagebox.showinfo(
                "Buat Master Password",
                "Belum ada Key Manager di komputer ini.\n"
                "Buat master password untuk melindungi semua kunci enkripsi kamu."
            )
            while True:
                pw1 = simpledialog.askstring("Master Password Baru", "Masukkan master password:", show="*")
                if pw1 is None:
                    return False
                if len(pw1) < 6:
                    messagebox.showerror("Terlalu pendek", "Gunakan minimal 6 karakter.")
                    continue
                pw2 = simpledialog.askstring("Konfirmasi", "Ulangi master password:", show="*")
                if pw2 is None:
                    return False
                if pw1 != pw2:
                    messagebox.showerror("Tidak cocok", "Password tidak sama, coba lagi.")
                    continue
                self.key_manager.create_new(pw1)
                return True
        else:
            for _ in range(5):
                pw = simpledialog.askstring("Buka Key Manager", "Masukkan master password:", show="*")
                if pw is None:
                    return False
                try:
                    self.key_manager.unlock(pw)
                    return True
                except ValueError as exc:
                    messagebox.showerror("Gagal", str(exc))
            messagebox.showerror("Gagal", "Terlalu banyak percobaan gagal.")
            return False

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f5f7fb")
        style.configure("Panel.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("TLabel", background="#f5f7fb", foreground="#172033", font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background="#ffffff", foreground="#172033", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#f5f7fb", foreground="#172033", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#f5f7fb", foreground="#56657f", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=(14, 8))
        style.configure("Primary.TButton", font=("Segoe UI", 12, "bold"), padding=(18, 12))
        style.configure("Info.TLabel", background="#ffffff", foreground="#1a6b3c", font=("Segoe UI", 9))

    def clear(self):
        for widget in self.winfo_children():
            widget.destroy()

    def header(self, title, subtitle):
        wrap = ttk.Frame(self, padding=(28, 24, 28, 8))
        wrap.pack(fill=X)
        ttk.Label(wrap, text=title, style="Title.TLabel").pack(anchor=W)
        ttk.Label(wrap, text=subtitle, style="Subtitle.TLabel").pack(anchor=W, pady=(4, 0))

    def status_bar(self):
        bar = ttk.Frame(self, padding=(28, 6))
        bar.pack(fill=X, side="bottom")
        ttk.Label(bar, textvariable=self.status, style="Subtitle.TLabel").pack(anchor=W)

    # ── Home ──────────────────────────────────

    def show_home(self):
        self.clear()
        self.header("Enkripsi_One_Mind", "Enkripsi/dekripsi file & pesan dengan AES-256-GCM.")
        panel = ttk.Frame(self, padding=28)
        panel.pack(fill=BOTH, expand=True)

        ttk.Button(
            panel, text="🔒 Enkripsi", style="Primary.TButton", command=self.show_encrypt
        ).pack(fill=X, pady=8)
        ttk.Button(
            panel, text="🔓 Decrypt", style="Primary.TButton", command=self.show_decrypt
        ).pack(fill=X, pady=8)
        ttk.Button(
            panel, text="🗝️ Key Manager", style="Primary.TButton", command=self.show_key_manager
        ).pack(fill=X, pady=8)
        ttk.Button(
            panel, text="Keluar", command=self.destroy
        ).pack(fill=X, pady=(24, 8))
        self.status_bar()

    # ── Encrypt ───────────────────────────────

    def show_encrypt(self):
        self.clear()
        self.header("Encrypt", "Pilih file atau tulis pesan, lalu enkripsi dengan kunci baru atau kunci lama.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        ttk.Label(panel, text="File untuk dienkripsi (opsional)", style="Panel.TLabel").pack(anchor=W)
        row_file = ttk.Frame(panel, style="Panel.TFrame")
        row_file.pack(fill=X, pady=(4, 12))
        ttk.Entry(row_file, textvariable=self.selected_file).pack(side=LEFT, fill=X, expand=True)
        ttk.Button(row_file, text="Pilih File", command=self.pick_encrypt_file).pack(side=RIGHT, padx=(8, 0))

        ttk.Label(panel, text="Atau tulis pesan", style="Panel.TLabel").pack(anchor=W)
        self.message_text = tk.Text(panel, height=6, wrap="word", font=("Segoe UI", 10))
        self.message_text.pack(fill=BOTH, expand=True, pady=(4, 12))

        key_frame = ttk.Frame(panel, style="Panel.TFrame")
        key_frame.pack(fill=X, pady=(0, 12))
        ttk.Label(key_frame, text="Sumber kunci", style="Panel.TLabel").pack(anchor=W)
        ttk.Radiobutton(
            key_frame, text="Buat kunci baru (disimpan otomatis ke Key Manager)",
            variable=self.encrypt_key_choice, value="new", command=self._refresh_encrypt_key_row
        ).pack(anchor=W)
        ttk.Radiobutton(
            key_frame, text="Pakai kunci yang sudah ada di Key Manager",
            variable=self.encrypt_key_choice, value="existing", command=self._refresh_encrypt_key_row
        ).pack(anchor=W)

        self.encrypt_key_row = ttk.Frame(panel, style="Panel.TFrame")
        self.encrypt_key_row.pack(fill=X, pady=(0, 12))
        self._refresh_encrypt_key_row()

        ttk.Checkbutton(
            panel, text="Ekspor juga sebagai file kunci portable (.key.txt) untuk dibagikan lewat DIPP",
            variable=self.export_key_var
        ).pack(anchor=W, pady=(0, 12))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X)
        ttk.Button(actions, text="Kembali", command=self.show_home).pack(side=LEFT)
        ttk.Button(
            actions, text="Enkripsi", style="Primary.TButton", command=self.encrypt_action
        ).pack(side=RIGHT)
        self.status_bar()

    def _refresh_encrypt_key_row(self):
        for w in self.encrypt_key_row.winfo_children():
            w.destroy()
        if self.encrypt_key_choice.get() == "new":
            ttk.Label(self.encrypt_key_row, text="Nama label kunci baru", style="Panel.TLabel").pack(anchor=W)
            ttk.Entry(self.encrypt_key_row, textvariable=self.new_key_label).pack(fill=X, pady=(4, 0))
        else:
            ttk.Label(self.encrypt_key_row, text="Pilih kunci", style="Panel.TLabel").pack(anchor=W)
            labels = [f'{k["label"]}  ({k["id"]})' for k in self.key_manager.keys]
            combo = ttk.Combobox(self.encrypt_key_row, values=labels, state="readonly")
            combo.pack(fill=X, pady=(4, 0))
            if labels:
                combo.current(0)
            combo.bind("<<ComboboxSelected>>", lambda e: self.encrypt_existing_key_id.set(
                self.key_manager.keys[combo.current()]["id"] if self.key_manager.keys else ""
            ))
            if labels:
                self.encrypt_existing_key_id.set(self.key_manager.keys[0]["id"])

    # ── Decrypt ───────────────────────────────

    def show_decrypt(self):
        self.clear()
        self.header("Decrypt", "Pilih file data terenkripsi (.bin) lalu tentukan sumber kuncinya.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        ttk.Label(panel, text="File data terenkripsi (.bin)", style="Panel.TLabel").pack(anchor=W)
        row_data = ttk.Frame(panel, style="Panel.TFrame")
        row_data.pack(fill=X, pady=(4, 12))
        ttk.Entry(row_data, textvariable=self.decrypt_data_var).pack(side=LEFT, fill=X, expand=True)
        ttk.Button(row_data, text="Pilih Data", command=self.pick_decrypt_data).pack(side=RIGHT, padx=(8, 0))

        key_frame = ttk.Frame(panel, style="Panel.TFrame")
        key_frame.pack(fill=X, pady=(0, 12))
        ttk.Label(key_frame, text="Sumber kunci", style="Panel.TLabel").pack(anchor=W)
        ttk.Radiobutton(
            key_frame, text="Pilih dari Key Manager", variable=self.decrypt_key_source,
            value="manager", command=self._refresh_decrypt_key_row
        ).pack(anchor=W)
        ttk.Radiobutton(
            key_frame, text="Impor file kunci (.key.txt)", variable=self.decrypt_key_source,
            value="file", command=self._refresh_decrypt_key_row
        ).pack(anchor=W)

        self.decrypt_key_row = ttk.Frame(panel, style="Panel.TFrame")
        self.decrypt_key_row.pack(fill=X, pady=(0, 12))
        self._refresh_decrypt_key_row()

        ttk.Label(panel, text="Folder output", style="Panel.TLabel").pack(anchor=W)
        row_out = ttk.Frame(panel, style="Panel.TFrame")
        row_out.pack(fill=X, pady=(4, 16))
        ttk.Entry(row_out, textvariable=self.output_dir).pack(side=LEFT, fill=X, expand=True)
        ttk.Button(row_out, text="Pilih Folder", command=self.pick_output_dir).pack(side=RIGHT, padx=(8, 0))

        ttk.Label(panel, text="Preview pesan teks", style="Panel.TLabel").pack(anchor=W)
        self.preview_text = tk.Text(panel, height=7, wrap="word", font=("Segoe UI", 10), state="disabled")
        self.preview_text.pack(fill=BOTH, expand=True, pady=(4, 12))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X)
        ttk.Button(actions, text="Kembali", command=self.show_home).pack(side=LEFT)
        ttk.Button(
            actions, text="Decrypt", style="Primary.TButton", command=self.decrypt_action
        ).pack(side=RIGHT)
        self.status_bar()

    def _refresh_decrypt_key_row(self):
        for w in self.decrypt_key_row.winfo_children():
            w.destroy()
        if self.decrypt_key_source.get() == "manager":
            ttk.Label(self.decrypt_key_row, text="Pilih kunci", style="Panel.TLabel").pack(anchor=W)
            labels = [f'{k["label"]}  ({k["id"]})' for k in self.key_manager.keys]
            combo = ttk.Combobox(self.decrypt_key_row, values=labels, state="readonly")
            combo.pack(fill=X, pady=(4, 0))
            if labels:
                combo.current(0)
                self.decrypt_existing_key_id.set(self.key_manager.keys[0]["id"])
            combo.bind("<<ComboboxSelected>>", lambda e: self.decrypt_existing_key_id.set(
                self.key_manager.keys[combo.current()]["id"] if self.key_manager.keys else ""
            ))
        else:
            ttk.Label(self.decrypt_key_row, text="File kunci (.key.txt)", style="Panel.TLabel").pack(anchor=W)
            row = ttk.Frame(self.decrypt_key_row, style="Panel.TFrame")
            row.pack(fill=X, pady=(4, 0))
            ttk.Entry(row, textvariable=self.decrypt_key_file_var).pack(side=LEFT, fill=X, expand=True)
            ttk.Button(row, text="Pilih File", command=self.pick_decrypt_key_file).pack(side=RIGHT, padx=(8, 0))

    # ── Key Manager page ──────────────────────

    def show_key_manager(self):
        self.clear()
        self.header("Key Manager", "Semua kunci enkripsi tersimpan aman di sini, terkunci dengan master password.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        columns = ("label", "algorithm", "created", "note")
        self.key_tree = ttk.Treeview(panel, columns=columns, show="headings", height=12)
        for col, text, width in (
            ("label", "Label", 220), ("algorithm", "Algoritma", 130),
            ("created", "Dibuat", 180), ("note", "Catatan", 220),
        ):
            self.key_tree.heading(col, text=text)
            self.key_tree.column(col, width=width, anchor=W)
        self.key_tree.pack(fill=BOTH, expand=True, pady=(4, 12))
        self._reload_key_tree()

        btn_row = ttk.Frame(panel, style="Panel.TFrame")
        btn_row.pack(fill=X, pady=(0, 8))
        ttk.Button(btn_row, text="Ganti Nama", command=self.rename_selected_key).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Hapus", command=self.delete_selected_key).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Ekspor ke File", command=self.export_selected_key).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Impor dari File", command=self.import_key_to_manager).pack(side=LEFT)

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X, pady=(12, 0))
        ttk.Button(actions, text="Kembali", command=self.show_home).pack(side=LEFT)
        ttk.Button(actions, text="Ganti Master Password", command=self.change_master_password).pack(side=RIGHT)
        self.status_bar()

    def _reload_key_tree(self):
        for row in self.key_tree.get_children():
            self.key_tree.delete(row)
        for k in self.key_manager.keys:
            self.key_tree.insert("", END, iid=k["id"], values=(k["label"], k["algorithm"], k["created"], k.get("note", "")))

    def _selected_key_id(self):
        sel = self.key_tree.selection()
        if not sel:
            messagebox.showwarning("Pilih kunci", "Pilih dulu satu kunci dari daftar.")
            return None
        return sel[0]

    def rename_selected_key(self):
        key_id = self._selected_key_id()
        if not key_id:
            return
        new_label = simpledialog.askstring("Ganti Nama", "Label baru:")
        if not new_label:
            return
        self.key_manager.rename_key(key_id, new_label)
        self._reload_key_tree()
        self.status.set("Label kunci diperbarui.")

    def delete_selected_key(self):
        key_id = self._selected_key_id()
        if not key_id:
            return
        if not messagebox.askyesno("Hapus kunci", "Yakin hapus kunci ini? Data yang dienkripsi dengan kunci ini tidak akan bisa dibuka lagi tanpa salinan kunci lain."):
            return
        self.key_manager.delete_key(key_id)
        self._reload_key_tree()
        self.status.set("Kunci dihapus.")

    def export_selected_key(self):
        key_id = self._selected_key_id()
        if not key_id:
            return
        save_path = filedialog.asksaveasfilename(
            title="Simpan file kunci", defaultextension=".key.txt",
            filetypes=[("Key file", "*.key.txt")], initialfile="exported.key.txt",
        )
        if not save_path:
            return
        out = self.key_manager.export_key_file(key_id, Path(save_path))
        self.status.set(f"Kunci diekspor ke {out}")
        messagebox.showinfo("Ekspor selesai", f"File kunci disimpan di:\n{out}\n\nJaga file ini agar tidak jatuh ke pihak lain.")

    def import_key_to_manager(self):
        path = filedialog.askopenfilename(title="Pilih file kunci", filetypes=[("Key file", "*.key.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            entry = self.key_manager.import_key_file(Path(path))
            self._reload_key_tree()
            self.status.set(f"Kunci '{entry['label']}' berhasil diimpor.")
        except Exception as exc:
            messagebox.showerror("Impor gagal", str(exc))

    def change_master_password(self):
        pw1 = simpledialog.askstring("Master Password Baru", "Master password baru:", show="*")
        if not pw1 or len(pw1) < 6:
            messagebox.showerror("Terlalu pendek", "Gunakan minimal 6 karakter.")
            return
        pw2 = simpledialog.askstring("Konfirmasi", "Ulangi master password baru:", show="*")
        if pw1 != pw2:
            messagebox.showerror("Tidak cocok", "Password tidak sama.")
            return
        self.key_manager.change_password(pw1)
        messagebox.showinfo("Berhasil", "Master password berhasil diganti.")

    # ── File pickers ──────────────────────────

    def pick_encrypt_file(self):
        path = filedialog.askopenfilename(title="Pilih file untuk dienkripsi")
        if path:
            self.selected_file.set(path)

    def pick_decrypt_data(self):
        path = filedialog.askopenfilename(
            title="Pilih file data terenkripsi",
            filetypes=[("Encrypted data", "*.bin"), ("All files", "*.*")],
        )
        if path:
            self.decrypt_data_var.set(path)

    def pick_decrypt_key_file(self):
        path = filedialog.askopenfilename(
            title="Pilih file kunci", filetypes=[("Key files", "*.key.txt"), ("All files", "*.*")],
        )
        if path:
            self.decrypt_key_file_var.set(path)

    def pick_output_dir(self):
        path = filedialog.askdirectory(title="Pilih folder output")
        if path:
            self.output_dir.set(path)

    # ── Actions ───────────────────────────────

    def encrypt_action(self):
        try:
            file_path = self.selected_file.get().strip()
            typed_text = self.message_text.get("1.0", END).strip()

            if file_path:
                source = Path(file_path)
                payload = source.read_bytes()
                filename = source.name
                payload_type = "file"
            elif typed_text:
                payload = typed_text.encode("utf-8")
                filename = "message.txt"
                payload_type = "text"
            else:
                raise ValueError("Masukkan file atau tulisan terlebih dahulu.")

            if self.encrypt_key_choice.get() == "new":
                key = secrets.token_bytes(32)
                label = self.new_key_label.get().strip() or f"{Path(filename).stem} — {now_iso()}"
                entry = self.key_manager.add_key(key, label, note=f"Dibuat saat mengenkripsi {filename}")
            else:
                key_id = self.encrypt_existing_key_id.get()
                if not key_id:
                    raise ValueError("Pilih kunci yang sudah ada di Key Manager, atau buat kunci baru.")
                key = self.key_manager.get_key_bytes(key_id)
                entry = next(k for k in self.key_manager.keys if k["id"] == key_id)

            base_name = Path(filename).stem
            save_path = filedialog.asksaveasfilename(
                title="Simpan file data terenkripsi",
                defaultextension=".bin",
                filetypes=[("Encrypted data", "*.bin")],
                initialfile=f"{base_name}_encrypted.bin",
            )
            if not save_path:
                return

            self.status.set("Sedang mengenkripsi payload dengan AES-256-GCM...")
            self.update_idletasks()

            envelope = encrypt_payload(payload, filename, payload_type, key)
            data_file = write_envelope(envelope, Path(save_path))

            exported_msg = ""
            if self.export_key_var.get():
                export_path = filedialog.asksaveasfilename(
                    title="Simpan file kunci portable", defaultextension=".key.txt",
                    filetypes=[("Key file", "*.key.txt")], initialfile=f"{base_name}.key.txt",
                )
                if export_path:
                    out = self.key_manager.export_key_file(entry["id"], Path(export_path))
                    exported_msg = f"\nFile kunci untuk dibagikan: {out}"

            self.status.set(f"Berhasil: {data_file} (kunci: {entry['label']})")
            messagebox.showinfo(
                "Encrypt selesai",
                f"Enkripsi berhasil.\n\nData terenkripsi: {data_file}\n"
                f"Kunci tersimpan di Key Manager sebagai: {entry['label']}{exported_msg}\n\n"
                f"File data ini aman diupload/dibagikan; kuncinya jangan disebar sembarangan."
            )
        except Exception as exc:
            self.status.set("Encrypt gagal.")
            messagebox.showerror("Encrypt gagal", str(exc))

    def decrypt_action(self):
        try:
            data_path = self.decrypt_data_var.get().strip()
            if not data_path:
                raise ValueError("Pilih file data terenkripsi terlebih dahulu.")
            envelope = json.loads(Path(data_path).read_text())

            if self.decrypt_key_source.get() == "manager":
                key_id = self.decrypt_existing_key_id.get()
                if not key_id:
                    raise ValueError("Pilih kunci dari Key Manager.")
                key = self.key_manager.get_key_bytes(key_id)
            else:
                key_file = self.decrypt_key_file_var.get().strip()
                if not key_file:
                    raise ValueError("Pilih file kunci untuk diimpor.")
                key_data = json.loads(Path(key_file).read_text())
                key = b64d(key_data["key_b64"])

            output_dir = self.output_dir.get().strip()
            if not output_dir:
                raise ValueError("Pilih folder output terlebih dahulu.")
            Path(output_dir).mkdir(parents=True, exist_ok=True)

            self.status.set("Memverifikasi kunci dan membuka payload...")
            self.update_idletasks()

            payload = decrypt_envelope(envelope, key)
            output_path = Path(output_dir) / safe_filename(envelope.get("filename") or "decrypted_message.txt")
            output_path.write_bytes(payload)

            self.status.set(f"Berhasil decrypt: {output_path}")
            self.preview_text.configure(state="normal")
            self.preview_text.delete("1.0", END)
            if envelope.get("payload_type") == "text":
                self.preview_text.insert("1.0", payload.decode("utf-8", errors="replace"))
            else:
                self.preview_text.insert("1.0", f"File berhasil disimpan ke:\n{output_path}")
            self.preview_text.configure(state="disabled")

            messagebox.showinfo(
                "Decrypt selesai",
                f"Payload berhasil dibuka.\n\nOutput: {output_path}\n\nFile: {envelope.get('filename', 'unknown')}"
            )
        except Exception as exc:
            self.status.set("Decrypt gagal.")
            messagebox.showerror("Decrypt gagal", str(exc))


# ──────────────────────────────────────────────
# Self-test (non-GUI, exercises the core engine + key manager)
# ──────────────────────────────────────────────

def run_self_test():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # Core envelope round-trip
        key = secrets.token_bytes(32)
        payload = "Halo penerima. Ini pesan rahasia.".encode("utf-8")
        envelope = encrypt_payload(payload, "message.txt", "text", key)
        data_file = write_envelope(envelope, tmp_path / "test")
        loaded_envelope = json.loads(data_file.read_text())
        opened = decrypt_envelope(loaded_envelope, key)
        assert opened == payload
        assert loaded_envelope["algorithm"] == ALGORITHM
        assert loaded_envelope["version"] == APP_VERSION

        # Wrong key must fail
        try:
            decrypt_envelope(loaded_envelope, secrets.token_bytes(32))
            raise AssertionError("Decrypt dengan kunci salah seharusnya gagal.")
        except ValueError:
            pass

        # Key manager round-trip
        global KEYSTORE_PATH, ONE_MIND_DIR
        ONE_MIND_DIR = tmp_path / ".one_mind"
        KEYSTORE_PATH = ONE_MIND_DIR / "keystore.enc"
        km = KeyManager()
        km.create_new("password-test-123")
        entry = km.add_key(key, "Kunci Test")

        km2 = KeyManager()
        km2.unlock("password-test-123")
        assert km2.get_key_bytes(entry["id"]) == key

        exported = km2.export_key_file(entry["id"], tmp_path / "exported")
        km3 = KeyManager()
        km3.create_new("another-password")
        imported = km3.import_key_file(exported)
        assert km3.get_key_bytes(imported["id"]) == key

        print("Self-test OK: envelope encrypt/decrypt, wrong-key rejection, dan key manager round-trip berhasil.")


if __name__ == "__main__":
    # Uncomment untuk menjalankan self-test tanpa GUI:
    # run_self_test()

    app = EnkripsiOneMindApp()
    app.mainloop()
