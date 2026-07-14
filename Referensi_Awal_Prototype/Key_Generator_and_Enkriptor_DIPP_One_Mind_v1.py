"""
Key_Generator_and_Enkriptor_DIPP_One_Mind
==========================================
Aplikasi asimetrik untuk ekosistem One_Mind, berbasis DIPP-KEM -- skema
buatan sendiri yang terinspirasi FrodoKEM tapi memakai geometric median
(Weiszfeld algorithm) sebagai ganti aljabar matriks LWE. Diadaptasi dari
notebook riset `DIPP_KEM_MIRIP_Frodo_02_07_v7.ipynb`.

CATATAN JUJUR (baca ini): DIPP-KEM adalah skema eksperimental buatan
sendiri, belum diaudit atau dianalisis oleh komunitas kriptografi. Jangan
jadikan satu-satunya lapisan pengaman untuk data yang benar-benar
berisiko tinggi tanpa tinjauan kriptografer independen. Untuk konteks
tugas akhir/riset/prototipe One_Mind ini sudah sesuai kebutuhan.

Peran app ini di One_Mind:
1. Generate Keypair -- dipakai saat registrasi ke Server_One_Mind. Public
   key (A_points + B + parameter) dikirim ke server; private key (x, w,
   delta) disimpan lokal di Key Manager terenkripsi.
2. Buku Kontak -- simpan public key milik pengguna lain (diunduh dari
   server) supaya bisa dipilih saat mau mengirim kunci.
3. Bungkus Kunci (encrypt) -- membungkus kunci simetrik AES (hasil
   ekspor dari Enkripsi_One_Mind, file .key.txt) memakai public key
   penerima, menghasilkan file "paket kunci" (.dwrap.json) yang aman
   dikirim lewat server.
4. Buka Kunci (decrypt) -- membuka paket kunci memakai private key
   sendiri, hasilnya file .key.txt yang bisa langsung diimpor ke Key
   Manager Enkripsi_One_Mind.

Reliabilitas: satu bit DIPP-KEM bisa salah decode dengan probabilitas
kecil tapi tidak nol (lihat correctness test di notebook). Karena kunci
AES 256-bit harus 100% benar semua bitnya, setiap bit di sini dikirim
`repeat` kali (default 5, ganjil) dan penerima memutuskan lewat voting
mayoritas -- menekan peluang galat total mendekati nol.
"""

import json
import os
import secrets
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from tkinter import (
    BOTH, END, LEFT, RIGHT, W, X,
    filedialog, messagebox, simpledialog,
)
import tkinter as tk
from tkinter import ttk

import numpy as np

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


APP_VERSION = 1
ALGORITHM_NAME = "DIPP-KEM-v1 (Weiszfeld, mirip FrodoKEM)"
KDF_ITERATIONS = 600_000

ONE_MIND_DIR = Path.home() / ".one_mind"
DIPP_KEYSTORE_PATH = ONE_MIND_DIR / "dipp_keystore.enc"

DEFAULT_PARAMS = {
    "dim": 3,
    "n_pub": 40,
    "coord_max": 1000,
    "w_range": (0.01, 0.15),
    "delta_range": (-0.1, 0.1),
    "q": 2 ** 16,
    "scale": 100,
    "error_bound": 50,
    "error_geser": 10,
    "repeat": 5,
}


def b64_ints(arr) -> list:
    return np.asarray(arr).tolist()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def derive_master_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


# ──────────────────────────────────────────────
# Bagian 1: DIPP-KEM core (diadaptasi dari notebook)
# ──────────────────────────────────────────────

def weighted_weiszfeld(points, weights, tol=1e-9, max_iter=500):
    points = np.array(points, dtype=float)
    weights = np.array(weights, dtype=float)
    y = np.average(points, axis=0, weights=weights)
    for _ in range(max_iter):
        d = np.linalg.norm(points - y, axis=1)
        d = np.where(d < 1e-12, 1e-12, d)
        w = weights / d
        y_new = (points * w[:, None]).sum(axis=0) / w.sum()
        if np.linalg.norm(y_new - y) < tol:
            y = y_new
            break
        y = y_new
    return y


def f_avg_dist(point, A_points):
    return float(np.mean(np.linalg.norm(A_points - point, axis=1)))


def geser_titik(point, jarak, rng):
    point = np.array(point, dtype=float)
    if jarak == 0:
        return point
    arah = rng.normal(size=point.shape[0])
    norm_arah = np.linalg.norm(arah)
    if norm_arah < 1e-12:
        return point
    arah = arah / norm_arah
    return point + arah * jarak


def keygen_int(A_points, dim, w_range, delta_range, coord_max, rng, error_geser=0):
    n_pub = len(A_points)
    x = rng.integers(0, coord_max, size=dim)
    w = rng.uniform(*w_range)
    delta = rng.uniform(*delta_range, size=n_pub)
    weights_A = 1.0 + delta
    weights = np.concatenate([weights_A, [w]])
    pts = np.vstack([A_points, x])
    B = weighted_weiszfeld(pts, weights)
    B = geser_titik(B, error_geser, rng)
    return x, w, delta, B


def compute_f(A_points, B_peer, x_self, w_self, delta_self):
    weights_A = 1.0 + delta_self
    weights = np.concatenate([weights_A, [1.0], [w_self]])
    pts = np.vstack([A_points, np.reshape(B_peer, (1, -1)), np.reshape(x_self, (1, -1))])
    med = weighted_weiszfeld(pts, weights)
    return f_avg_dist(med, A_points)


# ──────────────────────────────────────────────
# Bagian 2: Bit helpers + bungkus/buka kunci multi-bit dengan repetisi
# ──────────────────────────────────────────────

def bytes_to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits: list) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Jumlah bit tidak kelipatan 8.")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def generate_keypair(params: dict = None, rng=None) -> tuple:
    """Bangkitkan sepasang kunci DIPP-KEM. Return (public_dict, private_dict)."""
    params = dict(DEFAULT_PARAMS if params is None else params)
    rng = rng or np.random.default_rng(secrets.randbits(128))

    A_points = rng.integers(0, params["coord_max"], size=(params["n_pub"], params["dim"]))
    x, w, delta, B = keygen_int(
        A_points, params["dim"], params["w_range"], params["delta_range"],
        params["coord_max"], rng, error_geser=params["error_geser"],
    )

    public = {
        "algorithm": ALGORITHM_NAME,
        "version": APP_VERSION,
        "dim": params["dim"],
        "n_pub": params["n_pub"],
        "coord_max": params["coord_max"],
        "w_range": list(params["w_range"]),
        "delta_range": list(params["delta_range"]),
        "q": params["q"],
        "scale": params["scale"],
        "error_bound": params["error_bound"],
        "error_geser": params["error_geser"],
        "repeat": params["repeat"],
        "A_points": b64_ints(A_points),
        "B": b64_ints(B),
    }
    private = {
        "x": b64_ints(x),
        "w": float(w),
        "delta": b64_ints(delta),
    }
    return public, private


def wrap_key(public: dict, key_bytes: bytes, rng=None) -> dict:
    """Bungkus (enkripsi) sebuah kunci simetrik (bytes) memakai public key
    penerima. Return dict paket kunci (aman dikirim lewat server)."""
    rng = rng or np.random.default_rng(secrets.randbits(128))

    A_points = np.array(public["A_points"], dtype=float)
    B_recipient = np.array(public["B"], dtype=float)
    dim, coord_max = public["dim"], public["coord_max"]
    w_range, delta_range = tuple(public["w_range"]), tuple(public["delta_range"])
    q, scale, error_bound, error_geser, repeat = (
        public["q"], public["scale"], public["error_bound"], public["error_geser"], public["repeat"]
    )

    x_s, w_s, delta_s, B_s = keygen_int(A_points, dim, w_range, delta_range, coord_max, rng, error_geser)
    f_s = compute_f(A_points, B_recipient, x_s, w_s, delta_s)
    f_s_int = int(round(f_s * scale)) % q

    bits = bytes_to_bits(key_bytes)
    V_list = []
    for bit in bits:
        for _ in range(repeat):
            err = int(rng.integers(-error_bound, error_bound + 1))
            V = (f_s_int + err + bit * (q // 2)) % q
            V_list.append(V)

    return {
        "algorithm": ALGORITHM_NAME,
        "version": APP_VERSION,
        "created": now_iso(),
        "n_bits": len(bits),
        "repeat": repeat,
        "q": q,
        "scale": scale,
        "B_s": b64_ints(B_s),
        "V": V_list,
        "payload_label": public.get("label", ""),
    }


def unwrap_key(private_entry: dict, wrap: dict) -> bytes:
    """Buka paket kunci memakai private key sendiri. Return bytes kunci asli."""
    pub = private_entry["public"]
    priv = private_entry["private"]

    A_points = np.array(pub["A_points"], dtype=float)
    x_r = np.array(priv["x"], dtype=float)
    w_r = float(priv["w"])
    delta_r = np.array(priv["delta"], dtype=float)

    B_s = np.array(wrap["B_s"], dtype=float)
    q, scale, repeat = wrap["q"], wrap["scale"], wrap["repeat"]

    f_r = compute_f(A_points, B_s, x_r, w_r, delta_r)
    f_r_int = int(round(f_r * scale)) % q

    V_list = wrap["V"]
    n_bits = wrap["n_bits"]
    if len(V_list) != n_bits * repeat:
        raise ValueError("Paket kunci tidak konsisten (jumlah nilai V tidak sesuai).")

    bits = []
    for i in range(n_bits):
        votes = []
        for j in range(repeat):
            V = V_list[i * repeat + j]
            diff = (V - f_r_int) % q
            decoded = int(round(diff / (q // 2))) % 2
            votes.append(decoded)
        # voting mayoritas
        bits.append(1 if sum(votes) * 2 > len(votes) else 0)

    return bits_to_bytes(bits)


# ──────────────────────────────────────────────
# Bagian 3: Key Manager (private keys) + Buku Kontak (public keys orang lain)
# ──────────────────────────────────────────────

class DippKeyManager:
    def __init__(self):
        self.master_key = None
        self.salt = None
        self.iterations = KDF_ITERATIONS
        self.private_keys: list = []   # {id, label, created, public{...}, private{...}}
        self.contacts: list = []       # {id, label, created, public{...}}

    def exists_on_disk(self) -> bool:
        return DIPP_KEYSTORE_PATH.exists()

    def create_new(self, password: str):
        ONE_MIND_DIR.mkdir(parents=True, exist_ok=True)
        self.salt = os.urandom(16)
        self.master_key = derive_master_key(password, self.salt, self.iterations)
        self.private_keys = []
        self.contacts = []
        self._save()

    def unlock(self, password: str):
        raw = json.loads(DIPP_KEYSTORE_PATH.read_text())
        salt = base64_decode(raw["kdf_salt"])
        iterations = raw["kdf_iterations"]
        candidate = derive_master_key(password, salt, iterations)
        nonce = base64_decode(raw["nonce"])
        ciphertext = base64_decode(raw["ciphertext"])
        try:
            plaintext = AESGCM(candidate).decrypt(nonce, ciphertext, b"one_mind_dipp_keystore")
        except InvalidTag as exc:
            raise ValueError("Master password salah.") from exc
        self.salt, self.iterations, self.master_key = salt, iterations, candidate
        data = json.loads(plaintext.decode("utf-8"))
        self.private_keys = data["private_keys"]
        self.contacts = data["contacts"]

    def change_password(self, new_password: str):
        self.salt = os.urandom(16)
        self.iterations = KDF_ITERATIONS
        self.master_key = derive_master_key(new_password, self.salt, self.iterations)
        self._save()

    def _save(self):
        payload = json.dumps({"private_keys": self.private_keys, "contacts": self.contacts}).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.master_key).encrypt(nonce, payload, b"one_mind_dipp_keystore")
        raw = {
            "kdf_salt": base64_encode(self.salt),
            "kdf_iterations": self.iterations,
            "nonce": base64_encode(nonce),
            "ciphertext": base64_encode(ciphertext),
        }
        DIPP_KEYSTORE_PATH.write_text(json.dumps(raw, indent=2))

    # -- private keypair operations --------------------------------------

    def add_keypair(self, label: str, public: dict, private: dict) -> dict:
        entry = {
            "id": uuid.uuid4().hex[:12],
            "label": label or "Keypair tanpa nama",
            "created": now_iso(),
            "public": public,
            "private": private,
        }
        self.private_keys.append(entry)
        self._save()
        return entry

    def rename_keypair(self, key_id: str, new_label: str):
        for k in self.private_keys:
            if k["id"] == key_id:
                k["label"] = new_label
                self._save()
                return
        raise ValueError("Keypair tidak ditemukan.")

    def delete_keypair(self, key_id: str):
        before = len(self.private_keys)
        self.private_keys = [k for k in self.private_keys if k["id"] != key_id]
        if len(self.private_keys) == before:
            raise ValueError("Keypair tidak ditemukan.")
        self._save()

    def get_keypair(self, key_id: str) -> dict:
        for k in self.private_keys:
            if k["id"] == key_id:
                return k
        raise ValueError("Keypair tidak ditemukan.")

    def export_public_key(self, key_id: str, output_path: Path) -> Path:
        entry = self.get_keypair(key_id)
        bundle = dict(entry["public"])
        bundle["label"] = entry["label"]
        out = output_path.with_suffix(".dpub.json")
        out.write_text(json.dumps(bundle, indent=2))
        return out

    # -- contact book (public keys of others) -----------------------------

    def import_contact(self, path: Path, label: str = None) -> dict:
        bundle = json.loads(Path(path).read_text())
        entry = {
            "id": uuid.uuid4().hex[:12],
            "label": label or bundle.get("label") or f"Kontak: {Path(path).stem}",
            "created": now_iso(),
            "public": bundle,
        }
        self.contacts.append(entry)
        self._save()
        return entry

    def rename_contact(self, contact_id: str, new_label: str):
        for c in self.contacts:
            if c["id"] == contact_id:
                c["label"] = new_label
                self._save()
                return
        raise ValueError("Kontak tidak ditemukan.")

    def delete_contact(self, contact_id: str):
        before = len(self.contacts)
        self.contacts = [c for c in self.contacts if c["id"] != contact_id]
        if len(self.contacts) == before:
            raise ValueError("Kontak tidak ditemukan.")
        self._save()

    def get_contact(self, contact_id: str) -> dict:
        for c in self.contacts:
            if c["id"] == contact_id:
                return c
        raise ValueError("Kontak tidak ditemukan.")


def base64_encode(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode("ascii")


def base64_decode(text: str) -> bytes:
    import base64
    return base64.b64decode(text.encode("ascii"))


# ──────────────────────────────────────────────
# Bagian 4: GUI
# ──────────────────────────────────────────────

class DippApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Key_Generator_and_Enkriptor_DIPP_One_Mind")
        self.geometry("920x640")
        self.minsize(820, 560)
        self.configure(bg="#f5f7fb")

        self.km = DippKeyManager()

        self.new_keypair_label = tk.StringVar()
        self.status = tk.StringVar(value="Selamat datang.")

        self.wrap_contact_id = tk.StringVar()
        self.wrap_key_file_var = tk.StringVar()
        self.wrap_key_label_var = tk.StringVar()

        self.unwrap_privkey_id = tk.StringVar()
        self.unwrap_file_var = tk.StringVar()
        self.unwrap_label_var = tk.StringVar()

        self._build_styles()
        self.withdraw()
        if self._unlock_keystore():
            self.deiconify()
            self.show_home()
        else:
            self.destroy()

    # ── Keystore unlock flow ──────────────────

    def _unlock_keystore(self) -> bool:
        if not self.km.exists_on_disk():
            messagebox.showinfo(
                "Buat Master Password",
                "Belum ada Key Manager DIPP di komputer ini.\n"
                "Buat master password untuk melindungi private key kamu."
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
                self.km.create_new(pw1)
                return True
        else:
            for _ in range(5):
                pw = simpledialog.askstring("Buka Key Manager DIPP", "Masukkan master password:", show="*")
                if pw is None:
                    return False
                try:
                    self.km.unlock(pw)
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
        self.header(
            "Key_Generator_and_Enkriptor_DIPP_One_Mind",
            "PQC eksperimental (DIPP-KEM, mirip FrodoKEM berbasis geometric median)."
        )
        panel = ttk.Frame(self, padding=28)
        panel.pack(fill=BOTH, expand=True)

        ttk.Button(panel, text="🆕 Generate Keypair Baru", style="Primary.TButton",
                   command=self.show_generate).pack(fill=X, pady=6)
        ttk.Button(panel, text="🗝️ Key Manager (Private Key Saya)", style="Primary.TButton",
                   command=self.show_key_manager).pack(fill=X, pady=6)
        ttk.Button(panel, text="📇 Buku Kontak (Public Key Orang Lain)", style="Primary.TButton",
                   command=self.show_contacts).pack(fill=X, pady=6)
        ttk.Button(panel, text="📦 Bungkus Kunci (Enkripsi utk dikirim)", style="Primary.TButton",
                   command=self.show_wrap).pack(fill=X, pady=6)
        ttk.Button(panel, text="📬 Buka Kunci (Dekripsi yg diterima)", style="Primary.TButton",
                   command=self.show_unwrap).pack(fill=X, pady=6)
        ttk.Button(panel, text="Keluar", command=self.destroy).pack(fill=X, pady=(20, 6))
        self.status_bar()

    # ── Generate Keypair ──────────────────────

    def show_generate(self):
        self.clear()
        self.header("Generate Keypair", "Dipakai sekali saat registrasi ke Server_One_Mind.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        ttk.Label(panel, text="Label keypair (mis. nama akun)", style="Panel.TLabel").pack(anchor=W)
        ttk.Entry(panel, textvariable=self.new_keypair_label).pack(fill=X, pady=(4, 16))

        ttk.Label(
            panel,
            text=(
                f"Parameter default: dim={DEFAULT_PARAMS['dim']}, n_pub={DEFAULT_PARAMS['n_pub']}, "
                f"coord_max={DEFAULT_PARAMS['coord_max']}, repeat={DEFAULT_PARAMS['repeat']}.\n"
                "Ini parameter dengan correctness tertinggi dari uji coba di notebook riset."
            ),
            style="Panel.TLabel", wraplength=760,
        ).pack(anchor=W, pady=(0, 16))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X)
        ttk.Button(actions, text="Kembali", command=self.show_home).pack(side=LEFT)
        ttk.Button(actions, text="Generate", style="Primary.TButton", command=self.generate_action).pack(side=RIGHT)
        self.status_bar()

    def generate_action(self):
        try:
            self.status.set("Membangkitkan keypair (Weiszfeld)... mohon tunggu.")
            self.update_idletasks()
            public, private = generate_keypair(DEFAULT_PARAMS)
            label = self.new_keypair_label.get().strip() or f"Keypair {now_iso()}"
            entry = self.km.add_keypair(label, public, private)
            self.status.set(f"Keypair '{entry['label']}' berhasil dibuat.")

            if messagebox.askyesno(
                "Keypair dibuat",
                f"Keypair '{entry['label']}' tersimpan di Key Manager.\n\n"
                "Ekspor public key sekarang untuk dikirim ke server / dibagikan?"
            ):
                save_path = filedialog.asksaveasfilename(
                    title="Simpan public key", defaultextension=".dpub.json",
                    filetypes=[("DIPP public key", "*.dpub.json")],
                    initialfile=f"{entry['label']}.dpub.json",
                )
                if save_path:
                    out = self.km.export_public_key(entry["id"], Path(save_path))
                    messagebox.showinfo("Ekspor selesai", f"Public key disimpan di:\n{out}")
            self.show_home()
        except Exception as exc:
            self.status.set("Generate gagal.")
            messagebox.showerror("Generate gagal", str(exc))

    # ── Key Manager (private) ─────────────────

    def show_key_manager(self):
        self.clear()
        self.header("Key Manager", "Private key kamu, tersimpan terenkripsi dengan master password.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        columns = ("label", "created", "n_pub", "coord_max")
        self.priv_tree = ttk.Treeview(panel, columns=columns, show="headings", height=12)
        for col, text, width in (
            ("label", "Label", 260), ("created", "Dibuat", 200),
            ("n_pub", "n_pub", 100), ("coord_max", "coord_max", 100),
        ):
            self.priv_tree.heading(col, text=text)
            self.priv_tree.column(col, width=width, anchor=W)
        self.priv_tree.pack(fill=BOTH, expand=True, pady=(4, 12))
        self._reload_priv_tree()

        btn_row = ttk.Frame(panel, style="Panel.TFrame")
        btn_row.pack(fill=X, pady=(0, 8))
        ttk.Button(btn_row, text="Ganti Nama", command=self.rename_selected_privkey).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Hapus", command=self.delete_selected_privkey).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Ekspor Public Key", command=self.export_selected_pubkey).pack(side=LEFT)

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X, pady=(12, 0))
        ttk.Button(actions, text="Kembali", command=self.show_home).pack(side=LEFT)
        ttk.Button(actions, text="Ganti Master Password", command=self.change_master_password).pack(side=RIGHT)
        self.status_bar()

    def _reload_priv_tree(self):
        for row in self.priv_tree.get_children():
            self.priv_tree.delete(row)
        for k in self.km.private_keys:
            pub = k["public"]
            self.priv_tree.insert("", END, iid=k["id"], values=(k["label"], k["created"], pub["n_pub"], pub["coord_max"]))

    def _selected_tree_id(self, tree):
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("Pilih dulu", "Pilih satu baris dari daftar.")
            return None
        return sel[0]

    def rename_selected_privkey(self):
        key_id = self._selected_tree_id(self.priv_tree)
        if not key_id:
            return
        new_label = simpledialog.askstring("Ganti Nama", "Label baru:")
        if not new_label:
            return
        self.km.rename_keypair(key_id, new_label)
        self._reload_priv_tree()
        self.status.set("Label diperbarui.")

    def delete_selected_privkey(self):
        key_id = self._selected_tree_id(self.priv_tree)
        if not key_id:
            return
        if not messagebox.askyesno("Hapus keypair", "Yakin? Semua paket kunci yang dikirim ke kamu dengan public key ini tidak akan bisa dibuka lagi."):
            return
        self.km.delete_keypair(key_id)
        self._reload_priv_tree()
        self.status.set("Keypair dihapus.")

    def export_selected_pubkey(self):
        key_id = self._selected_tree_id(self.priv_tree)
        if not key_id:
            return
        save_path = filedialog.asksaveasfilename(
            title="Simpan public key", defaultextension=".dpub.json",
            filetypes=[("DIPP public key", "*.dpub.json")], initialfile="exported.dpub.json",
        )
        if not save_path:
            return
        out = self.km.export_public_key(key_id, Path(save_path))
        messagebox.showinfo("Ekspor selesai", f"Public key disimpan di:\n{out}")

    def change_master_password(self):
        pw1 = simpledialog.askstring("Master Password Baru", "Master password baru:", show="*")
        if not pw1 or len(pw1) < 6:
            messagebox.showerror("Terlalu pendek", "Gunakan minimal 6 karakter.")
            return
        pw2 = simpledialog.askstring("Konfirmasi", "Ulangi master password baru:", show="*")
        if pw1 != pw2:
            messagebox.showerror("Tidak cocok", "Password tidak sama.")
            return
        self.km.change_password(pw1)
        messagebox.showinfo("Berhasil", "Master password berhasil diganti.")

    # ── Buku Kontak ────────────────────────────

    def show_contacts(self):
        self.clear()
        self.header("Buku Kontak", "Public key milik pengguna lain (diunduh dari server / dibagikan langsung).")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        columns = ("label", "created", "n_pub", "coord_max")
        self.contact_tree = ttk.Treeview(panel, columns=columns, show="headings", height=12)
        for col, text, width in (
            ("label", "Label", 260), ("created", "Ditambahkan", 200),
            ("n_pub", "n_pub", 100), ("coord_max", "coord_max", 100),
        ):
            self.contact_tree.heading(col, text=text)
            self.contact_tree.column(col, width=width, anchor=W)
        self.contact_tree.pack(fill=BOTH, expand=True, pady=(4, 12))
        self._reload_contact_tree()

        btn_row = ttk.Frame(panel, style="Panel.TFrame")
        btn_row.pack(fill=X, pady=(0, 8))
        ttk.Button(btn_row, text="Impor Public Key (.dpub.json)", command=self.import_contact_action).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Ganti Nama", command=self.rename_selected_contact).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Hapus", command=self.delete_selected_contact).pack(side=LEFT)

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X, pady=(12, 0))
        ttk.Button(actions, text="Kembali", command=self.show_home).pack(side=LEFT)
        self.status_bar()

    def _reload_contact_tree(self):
        for row in self.contact_tree.get_children():
            self.contact_tree.delete(row)
        for c in self.km.contacts:
            pub = c["public"]
            self.contact_tree.insert("", END, iid=c["id"], values=(c["label"], c["created"], pub["n_pub"], pub["coord_max"]))

    def import_contact_action(self):
        path = filedialog.askopenfilename(title="Pilih file public key", filetypes=[("DIPP public key", "*.dpub.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            entry = self.km.import_contact(Path(path))
            self._reload_contact_tree()
            self.status.set(f"Kontak '{entry['label']}' berhasil diimpor.")
        except Exception as exc:
            messagebox.showerror("Impor gagal", str(exc))

    def rename_selected_contact(self):
        contact_id = self._selected_tree_id(self.contact_tree)
        if not contact_id:
            return
        new_label = simpledialog.askstring("Ganti Nama", "Label baru:")
        if not new_label:
            return
        self.km.rename_contact(contact_id, new_label)
        self._reload_contact_tree()

    def delete_selected_contact(self):
        contact_id = self._selected_tree_id(self.contact_tree)
        if not contact_id:
            return
        self.km.delete_contact(contact_id)
        self._reload_contact_tree()

    # ── Bungkus Kunci (encrypt) ────────────────

    def show_wrap(self):
        self.clear()
        self.header("Bungkus Kunci", "Enkripsi kunci AES (.key.txt dari Enkripsi_One_Mind) untuk penerima tertentu.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        ttk.Label(panel, text="Kirim ke (pilih dari Buku Kontak)", style="Panel.TLabel").pack(anchor=W)
        labels = [f'{c["label"]}  ({c["id"]})' for c in self.km.contacts]
        combo = ttk.Combobox(panel, values=labels, state="readonly")
        combo.pack(fill=X, pady=(4, 12))
        if labels:
            combo.current(0)
            self.wrap_contact_id.set(self.km.contacts[0]["id"])
        combo.bind("<<ComboboxSelected>>", lambda e: self.wrap_contact_id.set(
            self.km.contacts[combo.current()]["id"] if self.km.contacts else ""
        ))
        if not labels:
            ttk.Label(panel, text="(Belum ada kontak -- impor public key dulu di Buku Kontak.)",
                      style="Panel.TLabel").pack(anchor=W, pady=(0, 12))

        ttk.Label(panel, text="File kunci AES (.key.txt) dari Enkripsi_One_Mind", style="Panel.TLabel").pack(anchor=W)
        row = ttk.Frame(panel, style="Panel.TFrame")
        row.pack(fill=X, pady=(4, 16))
        ttk.Entry(row, textvariable=self.wrap_key_file_var).pack(side=LEFT, fill=X, expand=True)
        ttk.Button(row, text="Pilih File", command=self.pick_wrap_key_file).pack(side=RIGHT, padx=(8, 0))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X)
        ttk.Button(actions, text="Kembali", command=self.show_home).pack(side=LEFT)
        ttk.Button(actions, text="Bungkus & Simpan", style="Primary.TButton", command=self.wrap_action).pack(side=RIGHT)
        self.status_bar()

    def pick_wrap_key_file(self):
        path = filedialog.askopenfilename(title="Pilih file kunci", filetypes=[("Key file", "*.key.txt"), ("All files", "*.*")])
        if path:
            self.wrap_key_file_var.set(path)

    def wrap_action(self):
        try:
            contact_id = self.wrap_contact_id.get()
            if not contact_id:
                raise ValueError("Pilih penerima dari Buku Kontak dulu.")
            key_file = self.wrap_key_file_var.get().strip()
            if not key_file:
                raise ValueError("Pilih file kunci (.key.txt) dulu.")

            key_data = json.loads(Path(key_file).read_text())
            key_bytes = base64_decode(key_data["key_b64"])
            if len(key_bytes) not in (16, 24, 32):
                raise ValueError("Panjang kunci tidak dikenali (bukan kunci AES yang wajar).")

            contact = self.km.get_contact(contact_id)
            self.status.set("Membungkus kunci dengan DIPP-KEM (Weiszfeld)... mohon tunggu.")
            self.update_idletasks()

            wrap = wrap_key(contact["public"], key_bytes)
            wrap["payload_label"] = key_data.get("label", "")

            save_path = filedialog.asksaveasfilename(
                title="Simpan paket kunci", defaultextension=".dwrap.json",
                filetypes=[("DIPP wrapped key", "*.dwrap.json")],
                initialfile=f"untuk_{contact['label']}.dwrap.json",
            )
            if not save_path:
                return
            out = Path(save_path).with_suffix(".dwrap.json")
            out.write_text(json.dumps(wrap, indent=2))

            self.status.set(f"Berhasil: {out}")
            messagebox.showinfo(
                "Bungkus selesai",
                f"Paket kunci disimpan di:\n{out}\n\n"
                f"Kirim file ini ke {contact['label']} lewat server (upload sebagai kunci terenkripsi)."
            )
        except Exception as exc:
            self.status.set("Bungkus kunci gagal.")
            messagebox.showerror("Gagal", str(exc))

    # ── Buka Kunci (decrypt) ───────────────────

    def show_unwrap(self):
        self.clear()
        self.header("Buka Kunci", "Dekripsi paket kunci yang diterima, memakai private key kamu sendiri.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        ttk.Label(panel, text="Private key kamu (dari Key Manager)", style="Panel.TLabel").pack(anchor=W)
        labels = [f'{k["label"]}  ({k["id"]})' for k in self.km.private_keys]
        combo = ttk.Combobox(panel, values=labels, state="readonly")
        combo.pack(fill=X, pady=(4, 12))
        if labels:
            combo.current(0)
            self.unwrap_privkey_id.set(self.km.private_keys[0]["id"])
        combo.bind("<<ComboboxSelected>>", lambda e: self.unwrap_privkey_id.set(
            self.km.private_keys[combo.current()]["id"] if self.km.private_keys else ""
        ))
        if not labels:
            ttk.Label(panel, text="(Belum ada keypair -- generate dulu.)", style="Panel.TLabel").pack(anchor=W, pady=(0, 12))

        ttk.Label(panel, text="File paket kunci (.dwrap.json)", style="Panel.TLabel").pack(anchor=W)
        row = ttk.Frame(panel, style="Panel.TFrame")
        row.pack(fill=X, pady=(4, 16))
        ttk.Entry(row, textvariable=self.unwrap_file_var).pack(side=LEFT, fill=X, expand=True)
        ttk.Button(row, text="Pilih File", command=self.pick_unwrap_file).pack(side=RIGHT, padx=(8, 0))

        ttk.Label(panel, text="Label untuk kunci hasil buka (akan ditulis ke .key.txt)", style="Panel.TLabel").pack(anchor=W)
        ttk.Entry(panel, textvariable=self.unwrap_label_var).pack(fill=X, pady=(4, 16))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X)
        ttk.Button(actions, text="Kembali", command=self.show_home).pack(side=LEFT)
        ttk.Button(actions, text="Buka & Simpan sbg .key.txt", style="Primary.TButton", command=self.unwrap_action).pack(side=RIGHT)
        self.status_bar()

    def pick_unwrap_file(self):
        path = filedialog.askopenfilename(title="Pilih paket kunci", filetypes=[("DIPP wrapped key", "*.dwrap.json"), ("All files", "*.*")])
        if path:
            self.unwrap_file_var.set(path)

    def unwrap_action(self):
        try:
            privkey_id = self.unwrap_privkey_id.get()
            if not privkey_id:
                raise ValueError("Pilih private key kamu dulu.")
            wrap_file = self.unwrap_file_var.get().strip()
            if not wrap_file:
                raise ValueError("Pilih file paket kunci dulu.")

            wrap = json.loads(Path(wrap_file).read_text())
            entry = self.km.get_keypair(privkey_id)

            self.status.set("Membuka paket kunci dengan private key... mohon tunggu.")
            self.update_idletasks()

            key_bytes = unwrap_key(entry, wrap)
            label = self.unwrap_label_var.get().strip() or wrap.get("payload_label") or f"Kunci diterima {now_iso()}"

            # Format kompatibel langsung dengan Enkripsi_One_Mind (import Key Manager di sana)
            out_data = {
                "version": 3,
                "algorithm": "AES-256-GCM" if len(key_bytes) == 32 else f"AES-{len(key_bytes)*8}-GCM",
                "label": label,
                "key_b64": base64_encode(key_bytes),
            }
            save_path = filedialog.asksaveasfilename(
                title="Simpan sebagai file kunci (.key.txt)", defaultextension=".key.txt",
                filetypes=[("Key file", "*.key.txt")], initialfile=f"{label}.key.txt",
            )
            if not save_path:
                return
            out = Path(save_path).with_suffix(".key.txt")
            out.write_text(json.dumps(out_data, indent=2))

            self.status.set(f"Berhasil: {out}")
            messagebox.showinfo(
                "Buka kunci selesai",
                f"Kunci berhasil dibuka dan disimpan di:\n{out}\n\n"
                "Impor file ini langsung ke Key Manager di Enkripsi_One_Mind."
            )
        except Exception as exc:
            self.status.set("Buka kunci gagal.")
            messagebox.showerror("Gagal", str(exc))


# ──────────────────────────────────────────────
# Self-test (non-GUI): keygen -> wrap -> unwrap, harus kembali identik
# ──────────────────────────────────────────────

def run_self_test():
    global ONE_MIND_DIR, DIPP_KEYSTORE_PATH
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # keygen
        public, private = generate_keypair(DEFAULT_PARAMS)
        original_key = secrets.token_bytes(32)

        wrap = wrap_key(public, original_key)
        entry = {"public": public, "private": private}
        recovered_key = unwrap_key(entry, wrap)

        assert recovered_key == original_key, "Kunci hasil buka tidak sama dengan kunci asli!"
        print(f"Self-test 1 OK: wrap/unwrap 256-bit key identik (repeat={DEFAULT_PARAMS['repeat']}).")

        # keystore round-trip
        ONE_MIND_DIR = tmp_path / ".one_mind"
        DIPP_KEYSTORE_PATH = ONE_MIND_DIR / "dipp_keystore.enc"
        km = DippKeyManager()
        km.create_new("password-test-123")
        priv_entry = km.add_keypair("Test Keypair", public, private)

        pub_export = km.export_public_key(priv_entry["id"], tmp_path / "test_pub")

        km2 = DippKeyManager()
        km2.create_new("password-lain-456")
        contact = km2.import_contact(pub_export)

        wrap2 = wrap_key(contact["public"], original_key)
        recovered2 = unwrap_key(km.get_keypair(priv_entry["id"]), wrap2)
        assert recovered2 == original_key, "Round-trip lewat keystore + kontak gagal!"
        print("Self-test 2 OK: keystore & buku kontak round-trip berhasil.")

        # reliability over multiple random keys
        fails = 0
        trials = 20
        for _ in range(trials):
            k = secrets.token_bytes(32)
            w = wrap_key(public, k)
            r = unwrap_key(entry, w)
            if r != k:
                fails += 1
        print(f"Self-test 3: {trials - fails}/{trials} kunci acak 256-bit berhasil dibuka identik.")


if __name__ == "__main__":
    # Uncomment untuk self-test tanpa GUI:
    # run_self_test()

    app = DippApp()
    app.mainloop()
