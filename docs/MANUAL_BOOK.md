# Manual Sistem ONE_MIND

Versi dokumentasi: 18 Juli 2026
Dasar dokumentasi: perilaku kode pada `app/main.py`, `static/app.js`, konfigurasi Docker, dan skema SQLite aktual.

## 1. Ringkasan

ONE_MIND adalah prototipe web drive terenkripsi dengan:

- enkripsi/dekripsi file di browser;
- AES-256-GCM per versi file;
- DIPP-KEM prototipe untuk wrapping AES file key;
- password dan RSA proof-of-possession untuk login;
- certificate pengguna yang diterbitkan oleh PKI internal;
- approval dan pengelolaan akun oleh administrator;
- akses file `owner`, `editor`, dan `viewer`;
- upload ciphertext bertahap/chunked;
- SQLite dan file JSON envelope pada server.

Server tidak dirancang menerima plaintext file atau private key pengguna. Walaupun demikian, frontend berasal dari server sehingga operator yang mengubah JavaScript dapat mengakses data sensitif pada browser. Sistem ini masih prototipe, bukan produk siap menangani data sensitif.

## 2. Komponen

### Browser

Frontend statis menangani:

- pembuatan dan import identitas DIPP/RSA;
- penyimpanan token/username di `localStorage`;
- penyimpanan private key di RAM tab;
- enkripsi, dekripsi, wrapping, dan unwrapping key;
- pembagian ciphertext menjadi chunk;
- tampilan pengguna, file, akses, certificate, dan admin.

Web Crypto API digunakan untuk RSA, AES-GCM, SHA-256, dan random number. Implementasi DIPP berada di JavaScript aplikasi.

### Backend

FastAPI menangani:

- hash dan verifikasi password;
- pending-login dan bearer token;
- RSA nonce challenge dan signature verification;
- status/approval akun;
- penerbitan certificate;
- otorisasi file;
- upload chunk dan verifikasi SHA-256;
- penyimpanan envelope/wrapped key;
- audit tindakan administrator.

### Penyimpanan

Dalam mode lokal, `ONE_MIND_DATA_DIR=/app/data` berisi:

- `database/one_mind.sqlite3`
- `keys/server_secret.bin`
- `storage/<shard>/<file_id>.json`
- temporary upload directory yang dibuat aplikasi

TLS lokal memakai `/app/certs/server.crt` dan `/app/certs/server.key`.

## 3. Model Data

Tabel utama:

- `users`: profil, password hash, DIPP public key, RSA public key, status akun/certificate, timestamp administrasi;
- `administrators`: akun dan password hash admin;
- `admin_audit_log`: tindakan admin dan detail JSON;
- `certificates`: certificate PEM, serial, masa berlaku, dan status;
- `certificate_challenges`: nonce login terbaru per pengguna;
- `files`: owner, nama file, nama envelope, ukuran terenkripsi, waktu;
- `shares`: penerima, permission, dan wrapped key;
- `file_requests`: permintaan akses, pemilik, peminta, status, dan timestamp;
- `upload_sessions`: metadata dan progres upload chunk;
- tabel certificate request/revocation untuk state PKI terkait.

Envelope file JSON memuat metadata enkripsi seperti algoritma/IV serta `ciphertext_b64`. Wrapped key disimpan terpisah per penerima pada tabel `shares`.

## 4. Status Akun dan Certificate

Status akun yang digunakan aplikasi meliputi:

- `PENDING`: menunggu keputusan administrator;
- `ACTIVE`: dapat melanjutkan login;
- `REJECTED`: registrasi ditolak;
- `REVOKED`: akses akun dicabut;
- `DELETED`: soft-delete;
- status lain hanya jika telah didefinisikan kode/migrasi terkait.

Status certificate meliputi `NONE`, `ISSUED`, `REVOKED`, atau `EXPIRED` sesuai state backend. Certificate pertama diterbitkan otomatis setelah RSA challenge pertama berhasil. Login berikutnya mensyaratkan certificate terbaru aktif dan belum kedaluwarsa.

## 5. Memulai Aplikasi

### Lokal

```bash
docker compose up --build
```

Buka `https://localhost:8443`. Certificate self-signed dapat menimbulkan warning browser.

### Produksi

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Atur `.env` seperti dijelaskan pada [TLS_MIGRATION.md](TLS_MIGRATION.md). Jangan mengekspos port internal aplikasi dan jangan memakai wildcard allowed hosts.

## 6. Prosedur Administrator

### Setup pertama

1. Buka halaman aplikasi.
2. Jika belum ada admin, UI menampilkan setup administrator.
3. Masukkan username minimal 3 karakter dan password minimal 8 karakter.
4. Setelah setup berhasil, token admin disimpan di `localStorage`.

Setup tidak dapat dipakai lagi setelah administrator pertama tersedia.

### Login admin

Masukkan username dan password admin. Dashboard memuat pengguna yang dikelompokkan menurut status akun dan certificate.

### Operasi akun

Administrator dapat:

- mengubah display name, NIP, pangkat, dan jabatan;
- approve akun pending;
- reject akun dengan alasan opsional;
- revoke akun;
- restore akun;
- soft-delete akun;
- mengganti password administrator.

Tindakan dicatat ke `admin_audit_log`. Operasi status tidak menghapus private key yang mungkin sudah dimiliki pengguna dan tidak menarik kembali plaintext yang pernah diunduh.

## 7. Registrasi Pengguna

1. Isi username, display name, password, NIP, pangkat, dan jabatan.
2. Browser membuat DIPP keypair.
3. Browser membuat RSA 4096-bit keypair dengan RSASSA-PKCS1-v1_5/SHA-512.
4. Browser mengirim profil, password, dan kedua public key ke `/api/register` melalui HTTPS.
5. Server menyimpan hash password dan status `PENDING`.
6. Browser mengekspor identitas DIPP dan RSA Login Key.
7. Administrator harus menyetujui akun sebelum login lengkap dapat berhasil.

### Peringatan file identitas

Implementasi aktual mengekspor private key tanpa enkripsi password:

- file DIPP memuat `public_key` dan `private_key` dalam JSON;
- file RSA memuat public key PEM dan private key PKCS#8 base64.

Simpan kedua file di media terenkripsi dan terkontrol. Kehilangan DIPP key dapat membuat file lama tidak dapat dibuka. Pencurian key bersama kredensial terkait dapat memungkinkan penyalahgunaan akun/data.

Dokumentasi lama mengenai `.one-mind-key`, PBKDF2 600.000 iterasi, dan backup AES-GCM tidak menggambarkan alur aktual.

## 8. Login Pengguna

1. Pilih/import file identitas DIPP.
2. Pilih/import RSA Login Key yang sesuai.
3. Masukkan username dan password.
4. Browser mengirim password ke `/api/login` melalui HTTPS.
5. Server memverifikasi password dan status akun, lalu memberi pending-login token.
6. Browser meminta nonce melalui `/api/login/challenge`.
7. Browser menandatangani nonce memakai RSA private key.
8. Browser mengirim signature, nonce, dan RSA public key ke `/api/login/verify`.
9. Server memverifikasi kepemilikan key dan certificate.
10. Server menerbitkan bearer token utama.

Token dan username disimpan di `localStorage`. DIPP dan RSA private key berada di RAM tab. Auto-lock 15 menit belum aktif.

### Logout

Logout menghapus token/username user dari `localStorage` dan mengosongkan referensi DIPP/RSA/state key di RAM. Logout user tidak otomatis menghapus token admin jika sesi admin terpisah masih aktif.

Refresh atau menutup tab menghilangkan private key dari RAM, tetapi token persisten masih dapat membuat UI mengenali sesi sampai token kedaluwarsa atau ditolak server. Key harus diimpor kembali untuk operasi kriptografi.

## 9. Upload File

1. Pilih file dan tentukan visibilitas katalog. Default `Hide` menjaga file tidak terlihat oleh akun tanpa akses.
2. Browser menentukan ukuran chunk:
   - hingga 10 MB: maksimal 10 MB;
   - hingga 100 MB: 1 MB;
   - hingga 1 GB: 4 MB;
   - hingga 10 GB: 8 MB;
   - di atas 10 GB: 16 MB.
3. Browser membuat AES-256-GCM key dan IV acak.
4. File dienkripsi di browser.
5. Browser menghitung SHA-256 ciphertext.
6. AES key dibungkus untuk DIPP public key owner.
7. Browser membuat sesi upload, mengirim seluruh chunk base64, lalu melakukan finish.
8. Server menggabungkan chunk dan membandingkan hash.
9. Server menyimpan envelope ciphertext, metadata, dan wrapped key owner.

Catatan: frontend saat ini mengenkripsi file sebagai satu buffer sebelum ciphertext dibagi menjadi chunk. Untuk file sangat besar, konsumsi RAM browser tetap dapat tinggi meskipun transfer dilakukan bertahap.

## 10. Daftar dan Download File

`GET /api/files` mengembalikan file yang mempunyai record share untuk akun login, termasuk envelope. Saat download:

1. browser meminta detail file dan wrapped key milik akun;
2. DIPP private key dari RAM membuka wrapped AES key;
3. AES key mendekripsi envelope;
4. browser membuat `Blob` dan object URL untuk download plaintext.

Plaintext, AES key, ciphertext, dan buffer terkait dapat berada di RAM selama proses.

## 11. Share dan Permission

Owner memilih penerima serta `viewer` atau `editor`. Browser mengambil DIPP public key penerima, membuka AES key file secara lokal, kemudian membuat wrapped key penerima.

- `viewer`: download/decrypt.
- `editor`: download, rename, update, dan rotasi key.
- `owner`: seluruh operasi editor ditambah share, revoke, dan delete.

Server tidak menerima raw AES key pada alur normal.

### Permintaan file dari Direktori User

File yang tidak di-hide muncul sebagai metadata pada akun pemilik di tab Direktori User. User lain dapat menekan **Minta file**. Owner menerima notifikasi pada tab Permintaan File.

Saat owner menekan **Setujui & kirim kunci**:

1. browser owner membuka wrapped key owner menggunakan DIPP private key di RAM;
2. browser mengambil DIPP public key peminta;
3. browser membungkus AES key untuk peminta;
4. backend menyimpan wrapped key dan akses `viewer`;
5. file muncul pada daftar file peminta.

Owner dapat mengubah file menjadi hide atau tampil setelah upload. Mengubah menjadi hide membatalkan permintaan yang masih `PENDING`, tetapi tidak mencabut share yang sudah disetujui.

## 12. Revoke dan Rotasi

Revoke menghapus record akses penerima pada server. Revoke tidak dapat menghapus:

- plaintext yang sudah diunduh;
- screenshot/salinan pengguna;
- AES key atau ciphertext lama yang sudah disimpan.

Setelah revoke, update/rotate file agar versi baru memakai AES key baru dan hanya dibungkus untuk pengguna yang masih aktif pada file tersebut.

## 13. Update File

Owner atau editor dapat mengganti file:

1. file lama dibuka secara lokal;
2. replacement file dienkripsi dengan AES key baru;
3. browser mengambil seluruh daftar akses;
4. AES key baru dibungkus untuk setiap penerima aktif;
5. envelope dan semua wrapped key dikirim ke server.

Backend menolak update jika daftar penerima wrapped key tidak sama dengan daftar akses saat itu.

## 14. Penyimpanan Browser

### `localStorage`

- `om_token`
- `om_username`
- `om_admin_token`
- `om_admin_username`

Key lama `om_last_password_hint` dihapus pada login/logout, dan bukan sumber private key.

### RAM tab

- state token/user/admin;
- daftar file, user, certificate, dan dashboard admin;
- DIPP identity;
- RSA CryptoKey;
- pending token dan nonce;
- password/FormData selama pemrosesan;
- AES file key dan raw key sementara;
- plaintext/ciphertext/buffer file;
- file import dan object URL download.

Website origin lain tidak dapat membaca storage ini secara normal karena same-origin policy. JavaScript dari origin aplikasi, XSS, extension berizin, malware, DevTools pada perangkat terbuka, atau frontend server yang dimodifikasi dapat mengakses sebagian/seluruh data tersebut.

## 15. API

Semua endpoint file/user/certificate memerlukan `Authorization: Bearer <token>`, kecuali endpoint yang secara eksplisit publik atau memakai pending/admin token.

### Publik dan login

| Method | Endpoint | Fungsi |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/register` | Registrasi profil dan public key |
| POST | `/api/login` | Verifikasi password, menghasilkan pending token |
| POST | `/api/login/challenge` | Membuat nonce; pending token diperlukan |
| POST | `/api/login/verify` | Verifikasi RSA signature; pending token diperlukan |

### Pengguna dan certificate

| Method | Endpoint | Fungsi |
|---|---|---|
| GET | `/api/me` | Profil akun login dan DIPP public key |
| GET | `/api/users` | Direktori user lain dan DIPP public key |
| GET | `/api/users/{username}/public-key` | Public key target untuk share |
| GET | `/api/certificate/me` | Certificate terbaru pengguna |

### Upload dan file

| Method | Endpoint | Fungsi |
|---|---|---|
| POST | `/api/upload/start` | Membuat sesi upload chunk |
| POST | `/api/upload/chunk` | Mengirim chunk ciphertext base64 |
| POST | `/api/upload/finish` | Verifikasi hash dan simpan file |
| GET | `/api/files` | Daftar file yang dapat diakses |
| GET | `/api/files/{file_id}` | Envelope dan wrapped key akun |
| GET | `/api/files/{file_id}/access` | Daftar penerima/permission/public key |
| PATCH | `/api/files/{file_id}` | Rename oleh owner/editor |
| PATCH | `/api/files/{file_id}/visibility` | Hide/tampilkan file oleh owner |
| PUT | `/api/files/{file_id}` | Update envelope dan rotasi wrapped key |
| DELETE | `/api/files/{file_id}` | Delete oleh owner |
| POST | `/api/share` | Share oleh owner |
| DELETE | `/api/files/{file_id}/shares/{recipient}` | Revoke oleh owner |
| GET | `/api/file-catalog` | Metadata file yang ditampilkan owner |
| POST | `/api/files/{file_id}/requests` | Minta akses file katalog |
| GET | `/api/file-requests` | Permintaan masuk dan keluar |
| POST | `/api/file-requests/{request_id}/approve` | Setujui dengan wrapped key peminta |
| POST | `/api/file-requests/{request_id}/reject` | Tolak permintaan |

### Administrator

| Method | Endpoint | Fungsi |
|---|---|---|
| GET | `/api/admin/setup-status` | Memeriksa kebutuhan setup |
| POST | `/api/admin/setup` | Membuat administrator pertama |
| POST | `/api/admin/login` | Login admin |
| GET | `/api/admin/me` | Validasi sesi admin |
| POST | `/api/admin/change-password` | Mengganti password admin |
| GET | `/api/admin/users` | Daftar/group status pengguna |
| PATCH | `/api/admin/users/{username}` | Mengubah metadata pengguna |
| POST | `/api/admin/users/{username}/approve` | Approve |
| POST | `/api/admin/users/{username}/reject` | Reject |
| POST | `/api/admin/users/{username}/revoke` | Revoke |
| POST | `/api/admin/users/{username}/restore` | Restore |
| POST | `/api/admin/users/{username}/soft-delete` | Soft-delete |

## 16. Error Umum

### Akun belum aktif

Administrator belum approve akun atau akun sudah ditolak/dicabut/dihapus. Periksa dashboard admin.

### DIPP belum diimpor

Import file `.dipp` milik username tersebut. Jika file hilang dan tidak ada salinan aman, wrapped key lama mungkin tidak dapat dibuka.

### RSA Login Key tidak cocok

Pastikan file RSA berasal dari registrasi username tersebut. Backend membandingkan public key dan memverifikasi signature.

### Certificate tidak aktif/expired

Periksa status certificate. Implementasi tidak menyediakan alur self-service renewal lengkap; tindakan administrasi atau perubahan kode mungkin diperlukan sesuai status.

### Dekripsi gagal

Kemungkinan DIPP key salah, wrapped key rusak/telah dimodifikasi, envelope rusak, atau ciphertext tidak cocok.

### Token kedaluwarsa

Login ulang. Default masa berlaku 12 jam.

### Upload gagal

Periksa koneksi, ukuran/batas proxy, kelengkapan chunk, ruang disk, dan konsistensi SHA-256 ciphertext.

## 17. Backup dan Pemulihan

Backup server harus mencakup database, storage envelope, server secret, dan konfigurasi/certificate yang diperlukan deployment. Kehilangan `server_secret.bin` memutus validitas sesi lama tetapi bukan ciphertext.

Backup server saja tidak cukup untuk memulihkan private key pengguna. Setiap pengguna perlu menyimpan file DIPP dan RSA secara terpisah dalam media terenkripsi. Karena aplikasi belum mengenkripsi export, perlindungan harus diberikan oleh storage/OS/prosedur eksternal.

Uji restore pada lingkungan terisolasi. Jangan memulihkan data produksi ke host yang tidak dipercaya.

## 18. Batasan dan Rekomendasi

Sebelum produksi:

1. keluarkan database, CA/TLS private key, `server_secret.bin`, dan data aktif dari Git;
2. rotasi semua secret yang pernah terekspos;
3. enkripsi export private key;
4. aktifkan auto-lock;
5. perbaiki desain sesi/token;
6. tambahkan limit/quota dan rate limit persisten;
7. audit DIPP dan pertimbangkan KEM standar;
8. lakukan audit frontend/backend, dependency, deployment, dan host;
9. selaraskan SOP organisasi dengan ancaman operator server dan endpoint compromise.

Rincian risiko tersedia di [SECURITY.md](SECURITY.md).
