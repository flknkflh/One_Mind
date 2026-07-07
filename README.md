# ONE_MIND

ONE_MIND adalah prototype drive terenkripsi yang disatukan menjadi satu aplikasi web lokal. Aplikasi dijalankan dengan Docker, memakai HTTPS/TLS untuk transport, dan memakai enkripsi end-to-end di browser untuk isi file serta kunci file.

Dokumentasi lengkap tersedia di [docs/MANUAL_BOOK.md](docs/MANUAL_BOOK.md). Manual migrasi sertifikat ke Let's Encrypt/reverse proxy tersedia di [docs/TLS_MIGRATION.md](docs/TLS_MIGRATION.md).

## Jalankan Lokal

```powershell
docker compose up --build
```

Buka:

```text
https://localhost:8443
```

Browser akan memberi peringatan karena sertifikat lokal dibuat self-signed. Untuk pengujian lokal, lanjutkan ke halaman tersebut. Sertifikat berada di volume Docker `one_mind_certs`.

## Alur Pakai

1. Daftar akun.
   Browser membuat keypair DIPP-KEM. Public key DIPP dikirim ke server, private key DIPP disimpan lokal di browser dalam bentuk terenkripsi password.

2. Upload file.
   Browser membuat AES-256-GCM key acak, mengenkripsi file, lalu upload envelope terenkripsi ke server.

3. Bagikan file.
   Pemilik membuka kunci file lokal, lalu browser membungkus kunci file untuk public key DIPP penerima memakai metode DIPP.

4. Download file.
   Penerima mengunduh envelope terenkripsi dan wrapped key, membuka wrapped key dengan private key lokal, lalu dekripsi file di browser.

## Properti Keamanan

- Transport layer memakai HTTPS/TLS via Uvicorn SSL.
- Server menyimpan file dalam bentuk ciphertext saja.
- Server menyimpan public key pengguna, metadata file, dan wrapped key.
- Server tidak menyimpan private key pengguna.
- Server tidak menerima plaintext file atau raw AES file key.
- Enkripsi asimetrik/key wrapping memakai DIPP-KEM dari prototype kamu, dipakai untuk membungkus AES file key per penerima.
- Password akun masih dikirim ke server lewat TLS untuk autentikasi. Jika nanti ingin zero-knowledge login penuh, ubah autentikasi ke PAKE/SRP/OPAQUE atau certificate challenge-response.

## Data Persisten

Docker Compose memakai volume:

- `one_mind_data`: SQLite database, encrypted envelopes, server secret.
- `one_mind_certs`: sertifikat dan private key TLS lokal.

Reset total lokal:

```powershell
docker compose down -v
```

Perintah ini menghapus database, storage, dan sertifikat lokal.

## Backup Kunci User

Private key user disimpan di browser, bukan di server. Untuk pindah browser/perangkat:

1. Login di browser lama.
2. Buka tab **Kunci Lokal**.
3. Klik **Export encrypted private key**.
4. Buat password backup khusus minimal 12 karakter.
5. Simpan file `.one-mind-key` dan password backup secara terpisah.
6. Login di browser baru, buka tab **Kunci Lokal**, lalu import file backup.

File export dienkripsi di browser memakai PBKDF2-SHA-256 600.000 iterasi dan AES-256-GCM.

Backup server tetap perlu dilakukan terpisah dengan membackup volume `one_mind_data`.

## Troubleshooting

### Browser menolak HTTPS

Penyebab: sertifikat self-signed lokal.

Solusi lokal: buka `https://localhost:8443`, pilih Advanced, lalu lanjutkan. Untuk produksi, gunakan sertifikat CA resmi dari Let's Encrypt atau reverse proxy seperti Caddy/Nginx/Traefik.

### Login gagal karena "Private key lokal tidak ada"

Private key terenkripsi disimpan di localStorage browser tempat akun dibuat. Jika pindah perangkat/browser, akun server masih ada tetapi private key lokal tidak ikut. Untuk versi berikutnya, tambahkan fitur export/import encrypted private key.

### File tidak bisa didekripsi

Kemungkinan:

- password lokal salah sehingga private key gagal dibuka,
- file belum dibagikan ke akun tersebut,
- wrapped key bukan untuk private key akun tersebut,
- data storage rusak.

### Port 8443 sudah dipakai

Edit `docker-compose.yml`:

```yaml
ports:
  - "9443:8443"
```

Lalu buka `https://localhost:9443`.

## Siap ke Internet

Untuk deployment global:

1. Pakai domain tetap.
2. Ganti self-signed certificate dengan Let's Encrypt atau TLS termination di reverse proxy.
3. Set backup volume database dan storage.
4. Tambahkan audit log dan monitoring; rate limit login dasar sudah aktif.
5. Wajibkan prosedur export/import encrypted private key untuk pindah perangkat.
6. Pertimbangkan OPAQUE/SRP untuk autentikasi zero-knowledge password.

## Catatan Intranet

Untuk penggunaan intranet, tetap gunakan HTTPS/TLS. Self-signed certificate masih mengenkripsi traffic, tetapi sertifikat dari internal CA lebih baik agar browser user dapat memverifikasi server.

Rekomendasi tambahan:

- batasi port `8443` hanya untuk subnet intranet/VPN lewat firewall;
- jangan expose port aplikasi ke internet;
- set `ONE_MIND_ALLOWED_HOSTS` sesuai hostname/IP intranet;
- atur `ONE_MIND_SESSION_SECONDS` sesuai kebijakan sesi;
- pantau login gagal. Default rate limit adalah 8 kegagalan per 10 menit per IP+username.

## File Prototype Asli

Empat file prototype asli tetap disimpan di folder ini sebagai referensi:

- `Enkripsi_One_Mind_V_1.py`
- `Key_Generator_and_Enkriptor_DIPP_One_Mind_v1.py`
- `Server_One_Mind_Client.py`
- `Server_One_Mind_Server.py`
