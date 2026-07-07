# Manual Book ONE_MIND

Dokumen ini menjelaskan arsitektur aplikasi, mekanisme HTTP/API, alur keamanan, cara penggunaan, operasi Docker, backup, migrasi, dan troubleshooting.

## 1. Ringkasan Aplikasi

ONE_MIND adalah aplikasi web drive terenkripsi yang berjalan di Docker. File dienkripsi di browser sebelum dikirim ke server. Server menyimpan ciphertext, metadata file, public key user, dan wrapped key. Server tidak menyimpan plaintext file, private key user, atau raw AES file key.

Komponen utama:

- Frontend: `static/index.html`, `static/app.js`, `static/styles.css`.
- Backend: FastAPI di `app/main.py`.
- Runtime: Uvicorn HTTPS di container Docker.
- Database: SQLite di volume Docker `one_mind_data`.
- Storage file terenkripsi: JSON envelope di `/app/data/storage`.
- Sertifikat TLS lokal: volume Docker `one_mind_certs`.

## 2. Arsitektur Sistem

```text
Browser User
  |
  | HTTPS/TLS
  v
Docker Container: one_mind
  |
  | FastAPI/Uvicorn
  v
Backend API
  |
  +-- SQLite: /app/data/one_mind.sqlite3
  +-- Storage: /app/data/storage/*.json
  +-- Server secret: /app/data/server_secret.bin
  +-- Static UI: /app/static
```

### 2.1 Frontend

Frontend bertanggung jawab untuk:

- membuat keypair DIPP-KEM saat registrasi;
- menyimpan private key user di `localStorage` dalam bentuk terenkripsi;
- mengenkripsi file memakai AES-256-GCM sebelum upload;
- membungkus AES file key untuk pemilik/penerima memakai DIPP-KEM;
- membuka wrapped key dan mendekripsi file saat download;
- export/import encrypted private key untuk pindah perangkat.

Frontend memakai Web Crypto API browser:

- PBKDF2-SHA-256 untuk derivasi key lokal;
- AES-GCM untuk enkripsi private key lokal, file, dan backup private key.

### 2.2 Backend

Backend bertanggung jawab untuk:

- melayani file HTML/CSS/JS;
- registrasi dan login;
- validasi bearer token;
- menyimpan user, file, share, dan metadata;
- menyimpan envelope file terenkripsi;
- mengembalikan envelope dan wrapped key ke user yang berhak.

Backend tidak melakukan enkripsi/dekripsi isi file. Enkripsi file dilakukan di browser.

### 2.3 Database

SQLite membuat 3 tabel:

- `users`: `username`, `display_name`, `password_hash`, `public_key`, `created_at`.
- `files`: `id`, `owner`, `filename`, `envelope_name`, `encrypted_size`, `created_at`.
- `shares`: `id`, `file_id`, `owner`, `recipient`, `wrapped_key`, `created_at`.

`files` menyimpan metadata dan nama file envelope. Isi ciphertext berada di folder storage sebagai JSON.

### 2.4 Docker dan Volume

`docker-compose.yml` menjalankan service `one-mind`:

- port host `8443` diarahkan ke container `8443`;
- `ONE_MIND_DATA_DIR=/app/data`;
- volume `one_mind_data` dipasang ke `/app/data`;
- volume `one_mind_certs` dipasang ke `/app/certs`.

Volume penting:

- `one_mind_data`: database SQLite, envelope terenkripsi, server secret.
- `one_mind_certs`: certificate dan private key TLS lokal.

## 3. Mekanisme HTTP

Semua komunikasi browser ke backend memakai HTTPS saat dijalankan lewat Docker entrypoint. Endpoint backend mengirim dan menerima JSON.

### 3.1 Transport Layer

Container menjalankan Uvicorn dengan:

```text
--ssl-certfile /app/certs/server.crt
--ssl-keyfile /app/certs/server.key
```

Jika sertifikat belum ada, `scripts/entrypoint.sh` membuat self-signed certificate otomatis.

Untuk intranet, HTTPS tetap penting karena:

- password login dikirim ke server;
- bearer token dikirim di header;
- metadata dan envelope file lewat jaringan;
- jaringan internal tetap bisa memiliki risiko sniffing/MITM.

### 3.2 Header Keamanan

Backend menambahkan header:

- `Content-Security-Policy`: membatasi script/style/connect hanya dari origin sendiri.
- `X-Frame-Options: DENY`: mencegah clickjacking via iframe.
- `X-Content-Type-Options: nosniff`: mencegah MIME sniffing.
- `Referrer-Policy: no-referrer`: tidak membocorkan referrer.
- `Permissions-Policy`: menonaktifkan camera, microphone, geolocation, payment.
- `Strict-Transport-Security`: aktif jika request terdeteksi HTTPS.
- `Cache-Control: no-store`: untuk `/` dan `/api/*`.

### 3.3 Autentikasi HTTP

Login dan registrasi mengembalikan token:

```json
{
  "token": "base64_payload.hmac_signature",
  "username": "alice"
}
```

Token dikirim frontend pada request API berikutnya:

```http
Authorization: Bearer <token>
Content-Type: application/json
```

Token berisi:

- `username`;
- `nonce`;
- `exp` atau waktu kedaluwarsa.

Token ditandatangani memakai HMAC-SHA-256 dengan `server_secret.bin`. Default masa berlaku token adalah 12 jam, dikontrol oleh `ONE_MIND_SESSION_SECONDS`.

### 3.4 Rate Limit Login

Backend menyimpan penghitung login gagal in-memory per IP dan username.

Default:

- maksimal 8 kegagalan;
- dalam window 600 detik;
- dikontrol oleh `ONE_MIND_LOGIN_MAX_FAILURES` dan `ONE_MIND_LOGIN_WINDOW_SECONDS`.

Catatan: karena in-memory, counter reset saat container restart.

## 4. Endpoint HTTP/API

### 4.1 `GET /`

Mengembalikan halaman utama `static/index.html`.

Response:

```http
200 OK
Content-Type: text/html
Cache-Control: no-store
```

### 4.2 `GET /health`

Health check sederhana.

Response:

```json
{
  "ok": true,
  "transport": "HTTPS/TLS when run via docker entrypoint"
}
```

### 4.3 `POST /api/register`

Membuat akun baru. Browser sudah membuat public/private key sebelum request dikirim.

Request:

```json
{
  "username": "alice",
  "display_name": "Alice",
  "password": "password-user",
  "public_key": {
    "algorithm": "DIPP-KEM-v1 ...",
    "version": 1,
    "A_points": [],
    "B": []
  }
}
```

Backend menyimpan:

- username;
- display name;
- password hash PBKDF2-SHA-256;
- public key DIPP;
- waktu pembuatan.

Response:

```json
{
  "token": "...",
  "username": "alice"
}
```

### 4.4 `POST /api/login`

Memverifikasi username dan password.

Request:

```json
{
  "username": "alice",
  "password": "password-user"
}
```

Response sukses:

```json
{
  "token": "...",
  "username": "alice"
}
```

Response gagal:

```json
{
  "detail": "Username atau password salah."
}
```

### 4.5 `GET /api/me`

Butuh bearer token. Mengembalikan data akun login dan public key.

Response:

```json
{
  "username": "alice",
  "display_name": "Alice",
  "public_key": {},
  "created_at": "2026-07-07T..."
}
```

### 4.6 `GET /api/users`

Butuh bearer token. Mengembalikan daftar user lain untuk fitur share.

Response:

```json
[
  {
    "username": "bob",
    "display_name": "Bob",
    "public_key": {}
  }
]
```

### 4.6.1 `GET /api/users/{username}/public-key`

Butuh bearer token. Endpoint ini dipakai saat user A ingin membagikan file ke user B. Browser A meminta public key B ke server, lalu membungkus AES file key untuk B di sisi browser.

Response:

```json
{
  "username": "bob",
  "display_name": "Bob",
  "public_key": {}
}
```

### 4.7 `POST /api/files`

Butuh bearer token. Upload envelope file terenkripsi.

Request:

```json
{
  "filename": "dokumen.pdf",
  "envelope": {
    "version": 2,
    "algorithm": "AES-256-GCM",
    "filename": "dokumen.pdf",
    "mime": "application/pdf",
    "aad_b64": "...",
    "iv_b64": "...",
    "ciphertext_b64": "..."
  },
  "wrapped_key_for_owner": {
    "algorithm": "DIPP-KEM-v1 ...",
    "version": 1,
    "B_s": [],
    "V": []
  }
}
```

Backend menyimpan envelope sebagai JSON di storage, membuat row `files`, lalu membuat row `shares` untuk pemilik sendiri.

Response:

```json
{
  "file_id": "..."
}
```

### 4.8 `GET /api/files`

Butuh bearer token. Mengembalikan daftar file yang bisa diakses user.

Response:

```json
[
  {
    "id": "...",
    "owner": "alice",
    "filename": "dokumen.pdf",
    "encrypted_size": 12345,
    "created_at": "2026-07-07T..."
  }
]
```

### 4.9 `GET /api/files/{file_id}`

Butuh bearer token. Mengembalikan envelope terenkripsi dan wrapped key untuk user tersebut.

Response:

```json
{
  "id": "...",
  "owner": "alice",
  "filename": "dokumen.pdf",
  "envelope": {},
  "wrapped_key": {}
}
```

Backend hanya mengembalikan file jika ada row `shares` untuk user login.

### 4.10 `POST /api/share`

Butuh bearer token. Hanya owner file boleh membagikan file.

Request:

```json
{
  "file_id": "...",
  "recipient": "bob",
  "permission": "viewer",
  "wrapped_key": {}
}
```

Backend menyimpan wrapped key untuk recipient.

Response:

```json
{
  "ok": true
}
```

### 4.11 `GET /api/files/{file_id}/access`

Mengembalikan daftar user yang punya akses ke file, termasuk public key mereka. Dipakai saat rotate key agar AES key baru bisa dibungkus ulang untuk semua user aktif.

Role:

- `owner`: pemilik file, bisa read/update/delete/share/revoke/rotate.
- `editor`: bisa read dan update file dengan rotasi key.
- `viewer`: hanya read/download.

### 4.12 `PATCH /api/files/{file_id}`

Rename file. Diizinkan untuk `owner` dan `editor`.

Request:

```json
{
  "filename": "nama-baru.pdf"
}
```

### 4.13 `PUT /api/files/{file_id}`

Update isi file dan rotate AES key. Diizinkan untuk `owner` dan `editor`.

Client harus:

1. membuka file lama memakai private key lokal;
2. membuat AES key baru;
3. mengenkripsi file baru atau file lama yang sama;
4. meminta daftar akses aktif;
5. membungkus AES key baru untuk semua user aktif;
6. mengirim envelope baru dan wrapped key baru.

### 4.14 `DELETE /api/files/{file_id}`

Delete file untuk semua user. Hanya `owner`.

### 4.15 `DELETE /api/files/{file_id}/shares/{recipient}`

Cabut akses user tertentu. Hanya `owner`.

Setelah revoke, owner sebaiknya menjalankan **Rotate key file** agar user yang dicabut tidak bisa memakai key lama yang mungkin sudah pernah didapat.

## 5. Mekanisme Kriptografi

### 5.1 Registrasi

Alur:

1. User mengisi username, display name, dan password.
2. Browser membuat keypair DIPP-KEM.
3. Public key dikirim ke server.
4. Private key dienkripsi di browser memakai password akun.
5. Private key terenkripsi disimpan di `localStorage` dengan key `om_private_<username>`.
6. Server menyimpan public key dan hash password.

Private key lokal terenkripsi memakai:

- PBKDF2-SHA-256;
- salt 16 byte;
- 250.000 iterasi;
- AES-256-GCM;
- IV 12 byte.

Private key hasil decrypt tidak disimpan permanen. Saat user melakukan **Unlock private key session**, private key hanya hidup di memory tab browser selama sesi sementara, default 15 menit. Setelah refresh, logout, tab ditutup, atau timeout, private key plaintext hilang dari memory dan user harus unlock ulang.

### 5.2 Login

Alur:

1. Browser mengirim username dan password ke `/api/login` lewat HTTPS.
2. Server memverifikasi password hash.
3. Server mengembalikan bearer token.
4. Browser menyimpan token di `localStorage`.
5. Browser mencoba unlock private key lokal memakai password yang sama dan menyimpannya hanya di memory tab sementara.
6. Jika private key belum ada di browser baru, login tetap berhasil, tetapi user harus import encrypted private key sebelum membuka file lama.
7. Setelah refresh, logout, tab ditutup, atau timeout, user harus unlock ulang.

### 5.3 Upload File

Alur:

1. Browser membaca file dari perangkat user.
2. Browser membuat AES-256-GCM key acak per file.
3. Browser membuat IV 12 byte acak.
4. Browser membuat AAD berisi filename dan MIME type.
5. Isi file dienkripsi memakai AES-GCM.
6. AES file key dibungkus untuk public key pemilik memakai DIPP-KEM.
7. Browser mengirim envelope terenkripsi dan wrapped key ke server.
8. Server menyimpan envelope dan metadata.

Server tidak pernah menerima plaintext file.

### 5.4 Download File

Alur:

1. Browser meminta `/api/files/{file_id}`.
2. Server mengirim envelope terenkripsi dan wrapped key untuk user login.
3. User memasukkan password akun untuk membuka private key lokal.
4. Browser membuka wrapped key memakai private key DIPP.
5. Browser mendapat AES file key.
6. Browser mendekripsi envelope AES-GCM.
7. Browser membuat file download lokal.

### 5.5 Share File

Alur:

1. Owner memilih file dan recipient.
2. Owner memasukkan password akun untuk membuka private key lokal.
3. Browser owner membuka wrapped key milik owner.
4. Browser mendapat AES file key.
5. Browser membungkus ulang AES file key memakai public key recipient.
6. Browser mengirim wrapped key baru ke `/api/share`.
7. Server menyimpan akses recipient.

Server tidak melihat raw AES file key.

### 5.6 Export/Import Private Key

Export:

1. User login di browser lama.
2. User membuka tab **Kunci Lokal**.
3. User klik **Export encrypted private key**.
4. Browser membuka private key lokal memakai password akun.
5. Browser mengenkripsi ulang private key memakai password backup khusus.
6. Browser mengunduh file `.one-mind-key`.

Enkripsi backup:

- PBKDF2-SHA-256;
- 600.000 iterasi;
- AES-256-GCM;
- password backup minimal 12 karakter.

Import:

1. User login di browser baru.
2. User membuka tab **Kunci Lokal**.
3. User memilih file `.one-mind-key`.
4. Browser meminta password backup.
5. Browser meminta password akun.
6. Browser memverifikasi password akun ke server.
7. Browser membuka backup private key.
8. Browser menyimpan private key ke `localStorage` browser baru dalam bentuk terenkripsi password akun.

## 6. Manual Pengguna

### 6.1 Membuka Aplikasi

1. Pastikan container berjalan.
2. Buka:

```text
https://localhost:8443
```

3. Jika browser menampilkan warning sertifikat self-signed, pilih opsi lanjutan untuk melanjutkan.

Untuk produksi/intranet serius, gunakan sertifikat dari internal CA atau reverse proxy dengan sertifikat valid.

### 6.2 Membuat Akun

1. Buka halaman utama.
2. Isi username.
3. Isi nama tampilan.
4. Isi password minimal 8 karakter.
5. Klik **Buat akun dan keypair**.

Setelah registrasi:

- akun tersimpan di server;
- public key tersimpan di server;
- private key tersimpan di browser;
- user langsung login.

Penting: jangan hapus data browser sebelum export private key.

### 6.3 Login

1. Isi username.
2. Isi password.
3. Klik **Login**.

Jika login dari browser lama, kunci lokal biasanya tersedia.

Jika login dari browser baru, sistem akan memberi tahu bahwa kunci lokal belum ada. User harus import encrypted private key untuk membuka file lama.

### 6.4 Upload File

1. Login.
2. Buka tab **Upload Terenkripsi**.
3. Pilih file.
4. Klik **Enkripsi di browser dan upload**.
5. Tunggu notifikasi sukses.

File dienkripsi di browser sebelum dikirim ke server.

### 6.5 Melihat File

1. Login.
2. Buka tab **File Saya**.
3. Klik **Muat ulang** jika daftar belum terbaru.

Daftar menampilkan:

- total file yang bisa diakses;
- file milik sendiri;
- file yang dibagikan oleh user lain.

Gunakan kolom **Search** untuk mencari berdasarkan nama file, owner, role, atau tanggal. Gunakan filter untuk membatasi tampilan ke semua file, milik sendiri, dibagikan ke saya, editor, atau viewer.

Catatan keamanan: file milik akun lain hanya terlihat jika akun tersebut membagikan akses ke akun login.

### 6.5.1 Melihat Akun Lain

1. Login.
2. Buka tab **Direktori User**.
3. Gunakan search user untuk mencari nama atau username.
4. Klik **Pakai untuk share** untuk memilih user tersebut sebagai penerima di tab **Bagikan Kunci**.

Direktori user menampilkan akun yang bisa menerima share dan status public key. Direktori tidak membuka isi file milik user lain.

### 6.6 Download dan Dekripsi File

1. Buka tab **File Saya**.
2. Klik **Unduh & dekripsi**.
3. Masukkan password akun.
4. Browser akan mendekripsi file dan mengunduh hasilnya.

Jika gagal:

- pastikan password benar;
- pastikan private key lokal tersedia;
- pastikan file sudah dibagikan ke akun tersebut.

### 6.7 Membagikan File

1. Login sebagai pemilik file.
2. Buka tab **Bagikan Kunci**.
3. Pilih file.
4. Pilih penerima.
5. Pilih role `viewer` atau `editor`.
6. Klik **Bungkus kunci untuk penerima**.
7. Masukkan password akun.

Setelah berhasil, penerima akan melihat file di tab **File Saya** setelah refresh.

### 6.7.1 Kelola Akses

1. Buka tab **Bagikan Kunci**.
2. Pilih file.
3. Klik **Lihat akses**.
4. Klik **Cabut** untuk mencabut akses user.
5. Klik **Rotate key file** untuk mengenkripsi ulang file dengan AES key baru.

### 6.7.2 Update File

1. Buka tab **File Saya**.
2. Klik **Update & rotate key**.
3. Pilih file pengganti.
4. Masukkan password akun.
5. Browser membuka file lama, membuat AES key baru, mengenkripsi file pengganti, lalu membungkus ulang key untuk semua user yang masih punya akses.

### 6.7.3 Rename File

1. Buka tab **File Saya**.
2. Klik **Rename**.
3. Isi nama baru.

### 6.7.4 Delete File

1. Buka tab **File Saya**.
2. Klik **Delete**.
3. Konfirmasi penghapusan.

Delete hanya bisa dilakukan oleh owner.

### 6.8 Export Private Key

Gunakan ini sebelum pindah browser, pindah perangkat, reset browser, atau reinstall sistem.

1. Login di browser lama.
2. Buka tab **Kunci Lokal**.
3. Pastikan status menampilkan kunci lokal tersedia.
4. Klik **Export encrypted private key**.
5. Masukkan password akun.
6. Buat password backup minimal 12 karakter.
7. Ulangi password backup.
8. Simpan file `.one-mind-key`.

Rekomendasi penyimpanan:

- simpan file backup di media aman;
- simpan password backup di password manager;
- jangan simpan file backup dan password backup di tempat yang sama;
- jangan kirim file backup lewat kanal tidak aman.

### 6.9 Import Private Key

1. Login di browser/perangkat baru.
2. Buka tab **Kunci Lokal**.
3. Klik **Import encrypted private key**.
4. Pilih file `.one-mind-key`.
5. Masukkan password backup.
6. Masukkan password akun.
7. Tunggu notifikasi sukses.

Setelah import, browser baru bisa membuka file lama.

### 6.9.1 Unlock dan Lock Private Key Session

Private key terenkripsi tetap tersimpan di browser, tetapi private key yang sudah dibuka hanya disimpan sementara di memory tab.

Unlock:

1. Login.
2. Buka tab **Kunci Lokal**.
3. Klik **Unlock private key session**.
4. Masukkan password akun.

Setelah unlock, operasi download, share, update, rotate key, dan export key dapat memakai private key dari memory sementara.

Lock:

1. Buka tab **Kunci Lokal**.
2. Klik **Lock session sekarang**.

Private key plaintext akan hilang dari memory saat:

- user logout;
- tab/browser ditutup;
- halaman di-refresh;
- timeout session unlock habis;
- user klik lock manual.

### 6.10 Logout

Klik **Logout** di kanan atas.

Logout menghapus token sesi dari browser, tetapi tidak menghapus private key lokal.

### 6.11 Menghapus Kunci Lokal

Di tab **Kunci Lokal**, klik **Hapus kunci lokal perangkat ini**.

Peringatan:

- tindakan ini menghapus private key dari browser tersebut;
- akun server dan file server tidak ikut terhapus;
- jika belum punya backup `.one-mind-key`, file lama tidak bisa didekripsi dari browser itu.

## 7. Manual Operator/Admin

### 7.1 Menjalankan Aplikasi

```powershell
cd C:\Users\User\Documents\A_ONE_MIND_DOCKER_APP
docker compose up -d --build
```

Buka:

```text
https://localhost:8443
```

### 7.2 Melihat Status

```powershell
docker compose ps
```

### 7.3 Melihat Log

```powershell
docker compose logs -f
```

### 7.4 Stop Aplikasi

```powershell
docker compose down
```

Jangan gunakan `-v` kecuali ingin menghapus semua data.

### 7.5 Reset Total

```powershell
docker compose down -v
```

Ini menghapus:

- database;
- storage file terenkripsi;
- server secret;
- sertifikat lokal.

### 7.6 Konfigurasi Intranet

Copy `.env.example` menjadi `.env`, lalu sesuaikan:

```text
ONE_MIND_ALLOWED_HOSTS=localhost,127.0.0.1,one-mind.local,192.168.1.20
ONE_MIND_SESSION_SECONDS=43200
ONE_MIND_LOGIN_MAX_FAILURES=8
ONE_MIND_LOGIN_WINDOW_SECONDS=600
```

Rebuild:

```powershell
docker compose up -d --build
```

### 7.7 Firewall Intranet

Rekomendasi:

- buka hanya port `8443`;
- batasi akses ke subnet intranet/VPN;
- jangan expose langsung ke internet;
- gunakan internal DNS yang stabil;
- gunakan sertifikat dari internal CA jika memungkinkan.

### 7.8 Backup Server

Minimal backup volume `one_mind_data`.

Contoh backup dari container aktif:

```powershell
docker compose stop
docker run --rm --volumes-from one_mind -v "${PWD}:/backup" alpine tar czf /backup/one_mind_volumes.tar.gz /app/data /app/certs
docker compose up -d
```

Untuk produksi, buat jadwal backup otomatis dan simpan di lokasi terpisah.

### 7.9 Restore/Migrasi Server

Di server lama:

```powershell
docker compose stop
docker run --rm --volumes-from one_mind -v "${PWD}:/backup" alpine tar czf /backup/one_mind_volumes.tar.gz /app/data /app/certs
```

Pindahkan:

- folder project;
- file `one_mind_volumes.tar.gz`.

Di server baru:

```bash
cd A_ONE_MIND_DOCKER_APP
docker compose up -d --build
docker compose stop
docker run --rm --volumes-from one_mind -v "$PWD:/backup" alpine sh -c "cd / && tar xzf /backup/one_mind_volumes.tar.gz"
docker compose up -d
```

Jika memakai domain/sertifikat baru, `one_mind_certs` boleh dibuat ulang. Data utama ada di `one_mind_data`.

### 7.10 Migrasi TLS ke Let's Encrypt

Untuk pindah dari self-signed certificate lokal ke sertifikat profesional seperti Let's Encrypt, gunakan manual khusus:

[TLS_MIGRATION.md](TLS_MIGRATION.md)

Project sudah menyediakan:

- `docker-compose.prod.yml` untuk mode reverse proxy;
- `deploy/Caddyfile` untuk Caddy + Let's Encrypt;
- `.env.production.example` untuk konfigurasi domain dan email ACME;
- `ONE_MIND_TLS_MODE=off` agar aplikasi berjalan HTTP internal di belakang reverse proxy TLS.

## 8. Batasan dan Catatan Produksi

Yang sudah ada:

- HTTPS/TLS via Uvicorn SSL;
- self-signed certificate otomatis;
- security headers dasar;
- token sesi bertanda tangan dan expiring;
- rate limit login dasar;
- file encryption di browser;
- private key tidak disimpan di server;
- export/import encrypted private key.

Yang masih perlu dipertimbangkan untuk produksi besar:

- audit log login/upload/share/download;
- persistent rate limit memakai Redis atau database;
- admin dashboard;
- policy password lebih ketat;
- reset password yang tidak merusak akses private key;
- internal CA atau reverse proxy dengan sertifikat valid;
- backup otomatis terjadwal;
- monitoring disk, CPU, dan error;
- OPAQUE/SRP jika ingin autentikasi password zero-knowledge penuh.

## 9. Troubleshooting

### 9.1 Browser Menolak HTTPS

Penyebab: sertifikat self-signed.

Solusi lokal:

1. buka `https://localhost:8443`;
2. pilih Advanced;
3. lanjutkan ke situs.

Solusi produksi/intranet:

- gunakan internal CA;
- gunakan reverse proxy dengan sertifikat valid.

### 9.2 Upload Error `Cannot read properties of null`

Penyebab umum:

- browser memuat HTML lama tetapi JS baru;
- cache browser belum bersih setelah rebuild;
- container belum rebuild setelah perubahan static file.

Solusi:

```powershell
docker compose up -d --build
```

Lalu lakukan hard refresh:

```text
Ctrl + F5
```

### 9.3 Login Berhasil Tetapi File Tidak Bisa Dibuka

Kemungkinan:

- private key lokal belum ada di browser ini;
- user belum import `.one-mind-key`;
- password akun salah saat membuka private key;
- file belum dibagikan ke akun tersebut.

Solusi:

1. buka tab **Kunci Lokal**;
2. cek status kunci lokal;
3. import encrypted private key jika belum tersedia.

### 9.4 File Tidak Muncul di Penerima

Kemungkinan:

- owner belum share file;
- penerima belum klik **Muat ulang**;
- owner memilih penerima yang salah.

Solusi:

1. owner buka **Bagikan Kunci**;
2. pilih file dan penerima;
3. penerima buka **File Saya** dan klik **Muat ulang**.

### 9.5 Port 8443 Sudah Dipakai

Edit `docker-compose.yml`:

```yaml
ports:
  - "9443:8443"
```

Lalu:

```powershell
docker compose up -d --build
```

Buka:

```text
https://localhost:9443
```

### 9.6 Token Sesi Kedaluwarsa

Default token berlaku 12 jam. Login ulang untuk mendapat token baru.

Atur durasi:

```text
ONE_MIND_SESSION_SECONDS=43200
```

## 10. Checklist Operasional Produksi/Intranet

- Gunakan HTTPS.
- Set `ONE_MIND_ALLOWED_HOSTS`.
- Batasi port dengan firewall.
- Backup `one_mind_data` secara berkala.
- Instruksikan user export `.one-mind-key`.
- Simpan backup server dan backup key user secara terpisah.
- Monitor kapasitas disk.
- Monitor log container.
- Uji restore backup secara berkala.
- Jangan menjalankan `docker compose down -v` di server produksi kecuali memang ingin reset total.
