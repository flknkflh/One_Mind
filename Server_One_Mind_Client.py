"""
Server_One_Mind_Client.py
==========================
Client sungguhan untuk One_Mind -- connect lewat socket TCP+TLS ke
Server_One_Mind_Server.py yang berjalan di komputer lain (atau
komputer yang sama, utk testing).

Yang perlu disiapkan sebelum pakai app ini:
1. Server_One_Mind_Server.py sudah dijalankan di suatu komputer.
2. Kamu punya file sertifikat TLS server (server.crt) yang dicetak
   di layar server saat pertama kali dijalankan -- app ini
   memverifikasi PERSIS sertifikat itu (pinned), bukan asal percaya
   sertifikat siapa pun yang mengaku sebagai server.
3. (Untuk daftar akun) kamu sudah generate keypair & ekspor public key
   (.dpub.json) lewat Key_Generator_and_Enkriptor_DIPP_One_Mind.
4. (Untuk upload file terenkripsi) kamu sudah mengenkripsi file itu
   lebih dulu lewat Enkripsi_One_Mind, menghasilkan file .bin.

Lapis 1 (transport ke/dari server): TLS standar bawaan socket -- semua
request/response otomatis terenkripsi selama koneksi ini terbuka.
Lapis 2 (per file / antar pengguna): DIPP-KEM lewat
Key_Generator_and_Enkriptor_DIPP_One_Mind, tidak berubah.
"""

import json
import socket
import ssl
import base64
from pathlib import Path
from tkinter import (
    BOTH, END, LEFT, RIGHT, W, X, Y,
    filedialog, messagebox, simpledialog,
)
import tkinter as tk
from tkinter import ttk


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# ──────────────────────────────────────────────
# Framing pesan -- harus identik dengan Server_One_Mind_Server.py
# ──────────────────────────────────────────────

def send_msg(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ke server terputus.")
        buf += chunk
    return buf


def recv_msg(sock):
    length = int.from_bytes(recv_exact(sock, 4), "big")
    return json.loads(recv_exact(sock, length).decode("utf-8"))


class ServerConnection:
    """Satu koneksi TLS persisten ke Server_One_Mind_Server.py."""

    def __init__(self):
        self.sock = None

    def connect(self, host: str, port: int, cert_path: str):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False           # sertifikat self-signed, tidak terikat hostname asli
        context.load_verify_locations(cafile=cert_path)  # pin persis ke sertifikat ini
        raw_sock = socket.create_connection((host, port), timeout=10)
        self.sock = context.wrap_socket(raw_sock, server_hostname=host)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def call(self, action: str, **params):
        if not self.sock:
            raise RuntimeError("Belum terhubung ke server.")
        send_msg(self.sock, {"action": action, "params": params})
        resp = recv_msg(self.sock)
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "Server menolak permintaan."))
        return resp.get("result")


# ──────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────

class OneMindClientApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Server_One_Mind — Client")
        self.geometry("980x680")
        self.minsize(880, 600)
        self.configure(bg="#f5f7fb")

        self.conn = ServerConnection()
        self.current_user = None

        self._build_styles()
        self.show_connect()

    def call(self, action, **params):
        try:
            return self.conn.call(action, **params)
        except (ConnectionError, OSError) as exc:
            messagebox.showerror("Koneksi terputus", f"Koneksi ke server terputus: {exc}\nSilakan connect ulang.")
            self.show_connect()
            raise

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f5f7fb")
        style.configure("Panel.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("TLabel", background="#f5f7fb", foreground="#172033", font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background="#ffffff", foreground="#172033", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#f5f7fb", foreground="#172033", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#f5f7fb", foreground="#56657f", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 7))
        style.configure("Primary.TButton", font=("Segoe UI", 12, "bold"), padding=(16, 10))

    def clear(self):
        for w in self.winfo_children():
            w.destroy()

    def header(self, title, subtitle):
        wrap = ttk.Frame(self, padding=(24, 18, 24, 6))
        wrap.pack(fill=X)
        ttk.Label(wrap, text=title, style="Title.TLabel").pack(anchor=W)
        ttk.Label(wrap, text=subtitle, style="Subtitle.TLabel").pack(anchor=W, pady=(2, 0))

    def status_bar(self, text=""):
        bar = ttk.Frame(self, padding=(24, 6))
        bar.pack(fill=X, side="bottom")
        ttk.Label(bar, text=text or (f"Login sebagai: {self.current_user} (koneksi TLS aktif)" if self.current_user else "Belum terhubung"),
                  style="Subtitle.TLabel").pack(anchor=W)

    # ── Connect screen ─────────────────────────

    def show_connect(self):
        self.conn.close()
        self.current_user = None
        self.clear()
        self.header("Server_One_Mind", "Hubungkan ke server lewat socket TCP + TLS.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        host_var = tk.StringVar(value="127.0.0.1")
        port_var = tk.StringVar(value="5555")
        cert_var = tk.StringVar()

        ttk.Label(panel, text="Alamat server (IP/hostname)", style="Panel.TLabel").pack(anchor=W)
        ttk.Entry(panel, textvariable=host_var).pack(fill=X, pady=(4, 12))

        ttk.Label(panel, text="Port", style="Panel.TLabel").pack(anchor=W)
        ttk.Entry(panel, textvariable=port_var).pack(fill=X, pady=(4, 12))

        ttk.Label(panel, text="File sertifikat TLS server (server.crt, dari admin server)", style="Panel.TLabel").pack(anchor=W)
        row = ttk.Frame(panel, style="Panel.TFrame")
        row.pack(fill=X, pady=(4, 16))
        ttk.Entry(row, textvariable=cert_var).pack(side=LEFT, fill=X, expand=True)

        def pick_cert():
            p = filedialog.askopenfilename(title="Pilih server.crt", filetypes=[("Certificate", "*.crt *.pem"), ("All files", "*.*")])
            if p:
                cert_var.set(p)
        ttk.Button(row, text="Pilih File", command=pick_cert).pack(side=RIGHT, padx=(8, 0))

        def do_connect():
            try:
                port = int(port_var.get().strip())
                cert_path = cert_var.get().strip()
                if not cert_path:
                    raise ValueError("Pilih file sertifikat server dulu.")
                self.conn.connect(host_var.get().strip(), port, cert_path)
                messagebox.showinfo("Terhubung", "Koneksi TLS ke server berhasil dibuat.")
                self.show_start()
            except Exception as exc:
                messagebox.showerror("Gagal connect", str(exc))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X)
        ttk.Button(actions, text="Keluar Aplikasi", command=self.destroy).pack(side=LEFT)
        ttk.Button(actions, text="Connect", style="Primary.TButton", command=do_connect).pack(side=RIGHT)
        self.status_bar("Belum terhubung")

    # ── Start / Login / Register ──────────────

    def show_start(self):
        self.current_user = None
        self.clear()
        self.header("Server_One_Mind", "Terhubung -- silakan daftar atau login.")
        panel = ttk.Frame(self, padding=28)
        panel.pack(fill=BOTH, expand=True)
        ttk.Button(panel, text="Daftar Akun Baru", style="Primary.TButton", command=self.show_register).pack(fill=X, pady=8)
        ttk.Button(panel, text="Login dengan Sertifikat", style="Primary.TButton", command=self.show_login).pack(fill=X, pady=8)
        ttk.Button(panel, text="Putuskan Koneksi", command=self.show_connect).pack(fill=X, pady=(20, 8))
        self.status_bar("Terhubung, belum login")

    def show_register(self):
        self.clear()
        self.header("Daftar Akun Baru", "Perlu public key DIPP (.dpub.json) dari Key_Generator_and_Enkriptor_DIPP_One_Mind.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        name_var = tk.StringVar()
        ttk.Label(panel, text="Nama yang ditampilkan", style="Panel.TLabel").pack(anchor=W)
        ttk.Entry(panel, textvariable=name_var).pack(fill=X, pady=(4, 16))

        pubkey_var = tk.StringVar()
        ttk.Label(panel, text="File public key (.dpub.json)", style="Panel.TLabel").pack(anchor=W)
        row = ttk.Frame(panel, style="Panel.TFrame")
        row.pack(fill=X, pady=(4, 16))
        ttk.Entry(row, textvariable=pubkey_var).pack(side=LEFT, fill=X, expand=True)

        def pick():
            p = filedialog.askopenfilename(title="Pilih public key", filetypes=[("DIPP public key", "*.dpub.json"), ("All files", "*.*")])
            if p:
                pubkey_var.set(p)
        ttk.Button(row, text="Pilih File", command=pick).pack(side=RIGHT, padx=(8, 0))

        def submit():
            try:
                display_name = name_var.get().strip()
                if not display_name:
                    raise ValueError("Isi nama yang ditampilkan.")
                pk_path = pubkey_var.get().strip()
                if not pk_path:
                    raise ValueError("Pilih file public key.")
                public_key = json.loads(Path(pk_path).read_text())
                for req_field in ("A_points", "B", "dim", "n_pub", "coord_max", "q", "scale", "error_bound", "error_geser", "repeat"):
                    if req_field not in public_key:
                        raise ValueError("File public key tidak valid/lengkap.")

                result = self.call("register", display_name=display_name, public_key=public_key)

                cert_path = filedialog.asksaveasfilename(
                    title="Simpan sertifikat (dipakai utk login)", defaultextension=".json",
                    initialfile=f"{result['username']}.certificate.json",
                )
                if cert_path:
                    Path(cert_path).write_text(json.dumps(result["certificate"], indent=2))

                messagebox.showinfo(
                    "Registrasi berhasil",
                    f"Username : {result['username']}\n"
                    f"Password : {result['password']}\n\n"
                    "Catat/simpan password ini baik-baik (tidak ditampilkan lagi).\n"
                    "Sertifikat sudah disimpan -- pakai file itu untuk login berikutnya.\n\n"
                    "(Data ini dikirim lewat koneksi TLS yang sudah terenkripsi, aman dari penyadapan di jalur.)"
                )
                self.show_start()
            except Exception as exc:
                messagebox.showerror("Registrasi gagal", str(exc))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X)
        ttk.Button(actions, text="Kembali", command=self.show_start).pack(side=LEFT)
        ttk.Button(actions, text="Daftar", style="Primary.TButton", command=submit).pack(side=RIGHT)
        self.status_bar("Terhubung, belum login")

    def show_login(self):
        self.clear()
        self.header("Login", "Pilih file sertifikat yang kamu simpan saat registrasi.")
        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=28, pady=8)

        cert_var = tk.StringVar()
        ttk.Label(panel, text="File sertifikat (.json)", style="Panel.TLabel").pack(anchor=W)
        row = ttk.Frame(panel, style="Panel.TFrame")
        row.pack(fill=X, pady=(4, 16))
        ttk.Entry(row, textvariable=cert_var).pack(side=LEFT, fill=X, expand=True)

        def pick():
            p = filedialog.askopenfilename(title="Pilih file sertifikat", filetypes=[("Certificate", "*.json"), ("All files", "*.*")])
            if p:
                cert_var.set(p)
        ttk.Button(row, text="Pilih File", command=pick).pack(side=RIGHT, padx=(8, 0))

        def submit():
            try:
                cert_path = cert_var.get().strip()
                if not cert_path:
                    raise ValueError("Pilih file sertifikat dulu.")
                certificate = json.loads(Path(cert_path).read_text())
                result = self.call("login", certificate=certificate)
                self.current_user = result["username"]
                self.show_home()
            except Exception as exc:
                messagebox.showerror("Login gagal", str(exc))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill=X)
        ttk.Button(actions, text="Kembali", command=self.show_start).pack(side=LEFT)
        ttk.Button(actions, text="Login", style="Primary.TButton", command=submit).pack(side=RIGHT)
        self.status_bar("Terhubung, belum login")

    def logout(self):
        try:
            self.call("logout")
        except Exception:
            pass
        self.show_start()

    # ── Halaman 1: Profil & File Saya ─────────

    def show_home(self):
        self.clear()
        self.header(f"Halaman Saya — {self.current_user}", "Terhubung lewat socket TLS ke server.")

        nav = ttk.Frame(self, padding=(24, 0))
        nav.pack(fill=X)
        ttk.Button(nav, text="Jelajah Akun Lain", command=self.show_browse).pack(side=LEFT, padx=(0, 8))
        ttk.Button(nav, text="Manajemen Akun", command=self.show_account).pack(side=LEFT, padx=(0, 8))
        ttk.Button(nav, text="Keluar dari Akun", command=self.logout).pack(side=RIGHT)

        panel = ttk.Frame(self, style="Panel.TFrame", padding=18)
        panel.pack(fill=BOTH, expand=True, padx=24, pady=12)

        search_row = ttk.Frame(panel, style="Panel.TFrame")
        search_row.pack(fill=X, pady=(0, 10))
        ttk.Label(search_row, text="Cari nama file", style="Panel.TLabel").pack(side=LEFT)
        search_var = tk.StringVar()
        ttk.Entry(search_row, textvariable=search_var, width=28).pack(side=LEFT, padx=(6, 16))
        ttk.Label(search_row, text="Jenis", style="Panel.TLabel").pack(side=LEFT)
        kind_var = tk.StringVar(value="semua")
        ttk.Combobox(search_row, textvariable=kind_var, values=["semua", "plain", "encrypted"], width=12, state="readonly").pack(side=LEFT, padx=(6, 16))

        columns = ("filename", "folder", "visibility", "encrypted", "uploaded_at", "size")
        tree = ttk.Treeview(panel, columns=columns, show="headings", height=14)
        for col, text, width in (
            ("filename", "Nama", 220), ("folder", "Folder", 140), ("visibility", "Visibilitas", 100),
            ("encrypted", "Enkripsi", 90), ("uploaded_at", "Waktu", 170), ("size", "Ukuran (B)", 90),
        ):
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=W)
        tree.pack(fill=BOTH, expand=True, pady=(0, 10))

        def reload_tree():
            for row in tree.get_children():
                tree.delete(row)
            q = search_var.get().strip().lower()
            kf = kind_var.get()
            for item in self.call("list_own_items"):
                if q and q not in item["filename"].lower():
                    continue
                if kf == "plain" and item.get("encrypted"):
                    continue
                if kf == "encrypted" and not item.get("encrypted"):
                    continue
                tree.insert("", END, iid=item["id"], values=(
                    item["filename"], item["folder"], item["visibility"],
                    "ya" if item["encrypted"] else "tidak", item["uploaded_at"], item["size"]))
        reload_tree()
        ttk.Button(search_row, text="Cari", command=reload_tree).pack(side=LEFT)

        btn_row = ttk.Frame(panel, style="Panel.TFrame")
        btn_row.pack(fill=X)
        ttk.Button(btn_row, text="Upload File", command=lambda: self.show_upload(reload_tree)).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Buat Folder", command=lambda: self.create_folder_dialog(reload_tree)).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Unduh Terpilih", command=lambda: self.download_selected(tree)).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Hapus Terpilih", command=lambda: self.delete_selected(tree, reload_tree)).pack(side=LEFT)

        self.status_bar()

    def create_folder_dialog(self, reload_cb):
        name = simpledialog.askstring("Buat Folder", "Nama folder (mis. /Dokumen):")
        if not name:
            return
        self.call("create_folder", folder_path=name if name.startswith("/") else f"/{name}")
        reload_cb()

    def download_selected(self, tree):
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("Pilih dulu", "Pilih satu file dari daftar.")
            return
        try:
            result = self.call("download_file", file_id=sel[0])
        except Exception as exc:
            messagebox.showerror("Gagal", str(exc))
            return
        save_path = filedialog.asksaveasfilename(title="Simpan file", initialfile=result["filename"])
        if not save_path:
            return
        Path(save_path).write_bytes(b64d(result["data_b64"]))
        messagebox.showinfo("Berhasil", f"File diunduh ke:\n{save_path}" + (
            "\n\nIni file TERENKRIPSI -- buka dengan Enkripsi_One_Mind memakai kunci yang kamu simpan." if result["encrypted"] else ""
        ))

    def delete_selected(self, tree, reload_cb):
        sel = tree.selection()
        if not sel:
            return
        if messagebox.askyesno("Hapus", "Yakin hapus item ini?"):
            try:
                self.call("delete_file", file_id=sel[0])
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))
            reload_cb()

    def show_upload(self, reload_cb):
        win = tk.Toplevel(self)
        win.title("Upload File")
        win.geometry("480x440")
        frm = ttk.Frame(win, padding=18)
        frm.pack(fill=BOTH, expand=True)

        file_var = tk.StringVar()
        ttk.Label(frm, text="File untuk diupload").pack(anchor=W)
        row = ttk.Frame(frm)
        row.pack(fill=X, pady=(4, 12))
        ttk.Entry(row, textvariable=file_var).pack(side=LEFT, fill=X, expand=True)

        def pick():
            p = filedialog.askopenfilename(title="Pilih file")
            if p:
                file_var.set(p)
        ttk.Button(row, text="Pilih", command=pick).pack(side=RIGHT, padx=(8, 0))

        folder_var = tk.StringVar(value="/")
        ttk.Label(frm, text="Folder tujuan").pack(anchor=W)
        ttk.Entry(frm, textvariable=folder_var).pack(fill=X, pady=(4, 12))

        vis_var = tk.StringVar(value="public")
        ttk.Label(frm, text="Visibilitas").pack(anchor=W)
        ttk.Radiobutton(frm, text="Semua orang bisa lihat (publik)", variable=vis_var, value="public").pack(anchor=W)
        ttk.Radiobutton(frm, text="Catatan pribadi (privat)", variable=vis_var, value="private").pack(anchor=W)

        enc_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="File ini SUDAH dienkripsi dengan Enkripsi_One_Mind (upload apa adanya)", variable=enc_var).pack(anchor=W, pady=(8, 0))

        edit_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Izinkan siapa saja mengedit tanpa perlu izin (hanya berlaku utk publik+plain)", variable=edit_var).pack(anchor=W, pady=(8, 12))

        def submit():
            try:
                path = file_var.get().strip()
                if not path:
                    raise ValueError("Pilih file dulu.")
                data = Path(path).read_bytes()
                self.call(
                    "upload_file", filename=Path(path).name, folder=folder_var.get().strip() or "/",
                    visibility=vis_var.get(), encrypted=enc_var.get(), data_b64=b64e(data), edit_allowed=edit_var.get(),
                )
                win.destroy()
                reload_cb()
            except Exception as exc:
                messagebox.showerror("Upload gagal", str(exc))

        ttk.Button(frm, text="Upload", command=submit).pack(fill=X)

    # ── Halaman 2: Jelajah Akun Lain ──────────

    def show_browse(self):
        self.clear()
        self.header("Jelajah Akun Lain", "Hanya file publik yang tampil di sini.")
        nav = ttk.Frame(self, padding=(24, 0))
        nav.pack(fill=X)
        ttk.Button(nav, text="Kembali ke Halaman Saya", command=self.show_home).pack(side=LEFT)
        ttk.Button(nav, text="Keluar dari Akun", command=self.logout).pack(side=RIGHT)

        body = ttk.Frame(self, padding=24)
        body.pack(fill=BOTH, expand=True)

        left = ttk.Frame(body, style="Panel.TFrame", padding=12)
        left.pack(side=LEFT, fill=Y, padx=(0, 12))
        ttk.Label(left, text="Akun lain", style="Panel.TLabel").pack(anchor=W)
        user_list = tk.Listbox(left, width=28, height=22)
        user_list.pack(fill=Y, expand=True, pady=(6, 0))
        others = self.call("list_other_users")
        for o in others:
            user_list.insert(END, f'{o["display_name"]} ({o["username"]})')

        right = ttk.Frame(body, style="Panel.TFrame", padding=12)
        right.pack(side=LEFT, fill=BOTH, expand=True)
        ttk.Label(right, text="File publik", style="Panel.TLabel").pack(anchor=W)
        columns = ("filename", "encrypted", "uploaded_at", "size")
        tree = ttk.Treeview(right, columns=columns, show="headings", height=16)
        for col, text, width in (("filename", "Nama", 260), ("encrypted", "Enkripsi", 90), ("uploaded_at", "Waktu", 170), ("size", "Ukuran (B)", 100)):
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=W)
        tree.pack(fill=BOTH, expand=True, pady=(6, 10))

        selected_owner = {"username": None}

        def load_files(evt=None):
            sel = user_list.curselection()
            if not sel:
                return
            owner = others[sel[0]]["username"]
            selected_owner["username"] = owner
            for row in tree.get_children():
                tree.delete(row)
            for item in self.call("list_public_items", owner=owner):
                tree.insert("", END, iid=item["id"], values=(item["filename"], "ya" if item["encrypted"] else "tidak", item["uploaded_at"], item["size"]))

        user_list.bind("<<ListboxSelect>>", load_files)

        btn_row = ttk.Frame(right, style="Panel.TFrame")
        btn_row.pack(fill=X)

        def action_download():
            sel = tree.selection()
            if not sel:
                return
            try:
                result = self.call("download_file", file_id=sel[0])
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))
                return
            if result["encrypted"]:
                messagebox.showinfo("Perlu kunci", "File ini terenkripsi. Setelah diunduh, minta kunci ke pemilik.")
            save_path = filedialog.asksaveasfilename(title="Simpan file", initialfile=result["filename"])
            if save_path:
                Path(save_path).write_bytes(b64d(result["data_b64"]))

        def action_request_key():
            sel = tree.selection()
            if not sel:
                return
            try:
                self.call("request_key", file_id=sel[0])
                messagebox.showinfo("Terkirim", "Permintaan kunci sudah dikirim ke pemilik file.")
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))

        def action_download_delivered_key():
            sel = tree.selection()
            if not sel:
                return
            file_id = sel[0]
            try:
                notes = self.call("notifications")
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))
                return
            candidates = [n for n in notes if n["kind"] == "key_delivered" and n["data"].get("file_id") == file_id]
            if not candidates:
                messagebox.showinfo("Belum ada", "Belum ada kunci yang dikirim pemilik untuk file ini.")
                return
            request_id = candidates[-1]["data"]["request_id"]
            try:
                result = self.call("download_delivered_key", file_id=file_id, request_id=request_id)
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))
                return
            save_path = filedialog.asksaveasfilename(title="Simpan paket kunci", defaultextension=".dwrap.json", initialfile="kunci_diterima.dwrap.json")
            if save_path:
                Path(save_path).write_bytes(b64d(result["data_b64"]))
                messagebox.showinfo("Tersimpan", "Buka file ini di Key_Generator_and_Enkriptor_DIPP_One_Mind ('Buka Kunci').")

        def action_request_edit():
            sel = tree.selection()
            if not sel:
                return
            try:
                self.call("request_edit", file_id=sel[0])
                messagebox.showinfo("Terkirim", "Permintaan izin edit sudah dikirim ke pemilik.")
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))

        def action_edit_upload():
            sel = tree.selection()
            if not sel:
                return
            file_id = sel[0]
            try:
                allowed = self.call("can_edit", file_id=file_id)["can_edit"]
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))
                return
            if not allowed:
                messagebox.showwarning("Belum diizinkan", "Kamu belum punya izin edit untuk file ini.")
                return
            path = filedialog.askopenfilename(title="Pilih file versi baru")
            if not path:
                return
            try:
                self.call("replace_file_content", file_id=file_id, data_b64=b64e(Path(path).read_bytes()))
                messagebox.showinfo("Berhasil", "Isi file berhasil diperbarui.")
                load_files()
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))

        def action_export_contact_pubkey():
            owner = selected_owner["username"]
            if not owner:
                messagebox.showwarning("Pilih dulu", "Pilih akun di daftar sebelah kiri.")
                return
            try:
                pubkey = self.call("get_user_public_key", username=owner)
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))
                return
            save_path = filedialog.asksaveasfilename(title="Simpan public key kontak", defaultextension=".dpub.json", initialfile=f"{owner}.dpub.json")
            if save_path:
                Path(save_path).write_text(json.dumps(pubkey, indent=2))
                messagebox.showinfo("Tersimpan", "Impor file ini ke Buku Kontak di Key_Generator_and_Enkriptor_DIPP_One_Mind.")

        ttk.Button(btn_row, text="Unduh Data", command=action_download).pack(side=LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Minta Kunci", command=action_request_key).pack(side=LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Unduh Kunci Diterima", command=action_download_delivered_key).pack(side=LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Minta Izin Edit", command=action_request_edit).pack(side=LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Edit (Upload Versi Baru)", command=action_edit_upload).pack(side=LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Ekspor Public Key Akun Ini", command=action_export_contact_pubkey).pack(side=LEFT)

        self.status_bar()

    # ── Halaman 3: Manajemen Akun ──────────────

    def show_account(self):
        self.clear()
        self.header("Manajemen Akun", self.current_user)
        nav = ttk.Frame(self, padding=(24, 0))
        nav.pack(fill=X)
        ttk.Button(nav, text="Kembali ke Halaman Saya", command=self.show_home).pack(side=LEFT)
        ttk.Button(nav, text="Keluar dari Akun", command=self.logout).pack(side=RIGHT)

        body = ttk.Frame(self, padding=24)
        body.pack(fill=BOTH, expand=True)

        profile = ttk.Frame(body, style="Panel.TFrame", padding=14)
        profile.pack(fill=X, pady=(0, 12))
        ttk.Label(profile, text="Nama tampilan baru", style="Panel.TLabel").pack(anchor=W)
        name_var = tk.StringVar(value=self.current_user)
        ttk.Entry(profile, textvariable=name_var).pack(fill=X, pady=(4, 8))
        ttk.Button(profile, text="Simpan Nama", command=lambda: self._save_name(name_var.get())).pack(anchor=W)

        ttk.Separator(profile).pack(fill=X, pady=10)

        ttk.Label(profile, text="Perbarui public key DIPP (butuh konfirmasi password)", style="Panel.TLabel").pack(anchor=W)
        pk_var = tk.StringVar()
        row = ttk.Frame(profile, style="Panel.TFrame")
        row.pack(fill=X, pady=(4, 8))
        ttk.Entry(row, textvariable=pk_var).pack(side=LEFT, fill=X, expand=True)

        def pick_pk():
            p = filedialog.askopenfilename(title="Pilih public key baru", filetypes=[("DIPP public key", "*.dpub.json"), ("All files", "*.*")])
            if p:
                pk_var.set(p)
        ttk.Button(row, text="Pilih", command=pick_pk).pack(side=RIGHT, padx=(8, 0))
        ttk.Button(profile, text="Perbarui Public Key", command=lambda: self._update_pubkey(pk_var.get())).pack(anchor=W)

        notif_frame = ttk.Frame(body, style="Panel.TFrame", padding=14)
        notif_frame.pack(fill=BOTH, expand=True, pady=(0, 12))
        ttk.Label(notif_frame, text="Notifikasi & Permintaan Masuk", style="Panel.TLabel").pack(anchor=W)
        columns = ("kind", "message", "status", "created_at")
        notif_tree = ttk.Treeview(notif_frame, columns=columns, show="headings", height=8)
        for col, text, width in (("kind", "Jenis", 120), ("message", "Pesan", 380), ("status", "Status", 100), ("created_at", "Waktu", 170)):
            notif_tree.heading(col, text=text)
            notif_tree.column(col, width=width, anchor=W)
        notif_tree.pack(fill=BOTH, expand=True, pady=(6, 8))

        state = {"notes": []}

        def reload_notif():
            for row_ in notif_tree.get_children():
                notif_tree.delete(row_)
            state["notes"] = self.call("notifications")
            for i, n in enumerate(state["notes"]):
                notif_tree.insert("", END, iid=str(i), values=(n["kind"], n["message"], n["status"], n["created_at"]))
        reload_notif()

        def act_grant_key():
            sel = notif_tree.selection()
            if not sel:
                return
            note = state["notes"][int(sel[0])]
            if note["kind"] != "key_request":
                messagebox.showwarning("Bukan permintaan kunci", "Pilih notifikasi bertipe permintaan kunci.")
                return
            try:
                self.call("grant_key_request", file_id=note["data"]["file_id"], request_id=note["data"]["request_id"])
                messagebox.showinfo(
                    "Disetujui",
                    "Sekarang bungkus kunci AES file ini untuk peminta memakai Key_Generator_and_Enkriptor_DIPP_One_Mind "
                    "(pastikan public key peminta ada di Buku Kontak), lalu unggah hasilnya lewat 'Kirim Kunci'."
                )
                reload_notif()
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))

        def act_send_key():
            sel = notif_tree.selection()
            if not sel:
                return
            note = state["notes"][int(sel[0])]
            if note["kind"] not in ("key_request", "key_granted"):
                messagebox.showwarning("Bukan konteks kunci", "Pilih notifikasi permintaan kunci yang sudah disetujui.")
                return
            wrap_path = filedialog.askopenfilename(title="Pilih file paket kunci (.dwrap.json)", filetypes=[("DIPP wrapped key", "*.dwrap.json"), ("All files", "*.*")])
            if not wrap_path:
                return
            try:
                self.call("deliver_key", file_id=note["data"]["file_id"], request_id=note["data"]["request_id"], wrap_b64=b64e(Path(wrap_path).read_bytes()))
                messagebox.showinfo("Terkirim", "Kunci berhasil dikirim ke peminta.")
                reload_notif()
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))

        def act_approve_edit(approve: bool):
            sel = notif_tree.selection()
            if not sel:
                return
            note = state["notes"][int(sel[0])]
            if note["kind"] != "edit_request":
                messagebox.showwarning("Bukan permintaan edit", "Pilih notifikasi bertipe permintaan edit.")
                return
            try:
                self.call("decide_edit_request", file_id=note["data"]["file_id"], request_id=note["data"]["request_id"], approve=approve)
                reload_notif()
            except Exception as exc:
                messagebox.showerror("Gagal", str(exc))

        notif_btns = ttk.Frame(notif_frame, style="Panel.TFrame")
        notif_btns.pack(fill=X)
        ttk.Button(notif_btns, text="Setujui Permintaan Kunci", command=act_grant_key).pack(side=LEFT, padx=(0, 6))
        ttk.Button(notif_btns, text="Kirim Kunci (upload .dwrap.json)", command=act_send_key).pack(side=LEFT, padx=(0, 6))
        ttk.Button(notif_btns, text="Setujui Edit", command=lambda: act_approve_edit(True)).pack(side=LEFT, padx=(0, 6))
        ttk.Button(notif_btns, text="Tolak Edit", command=lambda: act_approve_edit(False)).pack(side=LEFT, padx=(0, 6))
        ttk.Button(notif_btns, text="Muat Ulang", command=reload_notif).pack(side=RIGHT)

        log_frame = ttk.Frame(body, style="Panel.TFrame", padding=14)
        log_frame.pack(fill=BOTH, expand=True)
        ttk.Label(log_frame, text="Log Transaksi (aktivitas kamu)", style="Panel.TLabel").pack(anchor=W)
        log_columns = ("time", "action", "detail")
        log_tree = ttk.Treeview(log_frame, columns=log_columns, show="headings", height=6)
        for col, text, width in (("time", "Waktu", 170), ("action", "Aksi", 140), ("detail", "Detail", 420)):
            log_tree.heading(col, text=text)
            log_tree.column(col, width=width, anchor=W)
        log_tree.pack(fill=BOTH, expand=True, pady=(6, 0))
        for i, entry in enumerate(reversed(self.call("audit_log_mine"))):
            log_tree.insert("", END, iid=str(i), values=(entry["time"], entry["action"], entry["detail"]))

        self.status_bar()

    def _save_name(self, new_name):
        if not new_name.strip():
            return
        try:
            self.call("rename_display_name", new_name=new_name.strip())
            messagebox.showinfo("Berhasil", "Nama tampilan diperbarui.")
            self.show_account()
        except Exception as exc:
            messagebox.showerror("Gagal", str(exc))

    def _update_pubkey(self, path):
        if not path.strip():
            messagebox.showwarning("Pilih file", "Pilih file public key dulu.")
            return
        pw = simpledialog.askstring("Konfirmasi", "Masukkan password akun untuk konfirmasi:", show="*")
        if pw is None:
            return
        try:
            new_pk = json.loads(Path(path).read_text())
            self.call("update_public_key", new_public_key=new_pk, password=pw)
            messagebox.showinfo("Berhasil", "Public key berhasil diperbarui.")
            self.show_account()
        except Exception as exc:
            messagebox.showerror("Gagal", str(exc))


if __name__ == "__main__":
    app = OneMindClientApp()
    app.mainloop()
