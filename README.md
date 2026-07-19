# ONE_MIND

ONE_MIND adalah prototipe web drive terenkripsi. Isi file dienkripsi dan didekripsi di browser, sedangkan server menyimpan ciphertext, metadata, public key, wrapped file key, status akun, dan sertifikat pengguna.

Dokumentasi:

- [Manual sistem](docs/MANUAL_BOOK.md)
- [Catatan keamanan](docs/SECURITY.md)
- [Panduan TLS dan deployment](docs/TLS_MIGRATION.md)
- [Konteks implementasi](Prompt.md)

> Status dokumentasi: diselaraskan dengan kode repository pada 18 Juli 2026. Implementasi saat ini berbeda dari rancangan lama yang menyimpan private key terenkripsi di `localStorage`.

## Menjalankan Secara Lokal

Persyaratan: Docker dan Docker Compose.

```bash
docker compose up --build
```

Buka `https://localhost:8443`. Mode lokal memakai sertifikat self-signed sehingga browser dapat menampilkan peringatan.

Data lokal dipasang dari:

- `./data` ke `/app/data`
- `./certs` ke `/app/certs`

Konfigurasi utama tersedia melalui `ONE_MIND_ALLOWED_HOSTS`, `ONE_MIND_SESSION_SECONDS`, `ONE_MIND_LOGIN_MAX_FAILURES`, dan `ONE_MIND_LOGIN_WINDOW_SECONDS`.

## Alur Sistem Saat Ini

### 1. Inisialisasi administrator

Administrator pertama dibuat melalui UI/API setup. Sesudah itu administrator dapat login, menyetujui atau menolak registrasi, mencabut/memulihkan akun, mengubah data akun, melakukan soft-delete, dan mengganti password admin.

### 2. Registrasi pengguna

Browser membuat dua identitas:

- keypair DIPP untuk membungkus AES file key;
- keypair RSA 4096-bit untuk proof-of-possession saat login.

Server menerima data identitas, DIPP public key, RSA public key, serta password melalui HTTPS. Password disimpan sebagai hash PBKDF2-SHA-256. Akun baru berstatus `PENDING` sampai diproses administrator.

Browser mengekspor dua file identitas pengguna. Pada implementasi saat ini, private key di dalam file tersebut **belum dienkripsi dengan password**. File harus diperlakukan sebagai secret berisiko tinggi.

### 3. Login

Login memiliki dua tahap:

1. Server memeriksa username, password, dan status akun lalu memberikan pending-login token.
2. Browser mengimpor RSA Login Key, meminta nonce, menandatangani nonce, dan server memverifikasi signature dengan RSA public key pengguna.

Setelah verifikasi berhasil, server menerbitkan bearer token utama. Saat login pertama yang valid, certificate pengguna diterbitkan otomatis jika belum ada.

Bearer token dan username disimpan di `localStorage`. DIPP/RSA private key tidak disimpan di `localStorage`; key yang diimpor hidup di RAM tab.

### 4. Upload

Browser:

1. membuat AES-256-GCM key acak;
2. mengenkripsi file;
3. menghitung SHA-256 ciphertext;
4. membungkus raw AES key untuk pemilik menggunakan DIPP public key;
5. mengirim ciphertext dalam beberapa chunk sesuai ukuran file;
6. menyelesaikan upload dengan envelope, hash, dan wrapped key pemilik.

Server memverifikasi hash ciphertext gabungan lalu menyimpan envelope ciphertext dan metadata file.

### 5. Download dan berbagi

Server hanya mengembalikan file kepada akun yang memiliki record akses. Browser membuka wrapped key memakai DIPP private key di RAM, lalu mendekripsi ciphertext.

Owner dapat membagikan file sebagai `viewer` atau `editor`. Owner membuka AES key secara lokal dan membungkusnya kembali untuk DIPP public key penerima. Owner dapat mencabut akses; rotasi key diperlukan untuk melindungi versi file berikutnya dari key lama yang mungkin sudah diperoleh penerima.

### 6. Update dan rotasi key

Owner atau editor dapat mengganti isi file. Browser membuat AES key baru, mengenkripsi ulang file, dan membuat wrapped key baru untuk semua pengguna yang masih mempunyai akses.

## Data di Browser

Persisten di `localStorage`:

- `om_token`
- `om_username`
- `om_admin_token`
- `om_admin_username`

Sementara di RAM tab:

- DIPP private/public identity yang diimpor;
- RSA Login private/public key yang diimpor atau dibuat;
- AES file key selama operasi file;
- plaintext file selama enkripsi/dekripsi;
- password/form data selama request;
- daftar file, envelope/ciphertext, daftar pengguna, dan metadata UI.

Auto-lock private key 15 menit belum aktif dalam kode saat ini. Key di RAM dibersihkan saat logout, refresh, tab ditutup, proses browser berhenti, atau state login direset.

## Data di Server

Server menyimpan:

- SQLite database pengguna, administrator, certificate, audit admin, file, share, dan sesi upload;
- hash password;
- DIPP dan RSA public key;
- ciphertext/envelope;
- wrapped AES key setiap penerima;
- `server_secret.bin` untuk menandatangani token;
- private key TLS dan private key CA pada deployment/repository saat ini.

Server tidak dirancang menyimpan private key pengguna atau plaintext file. Namun operator server dapat mengubah JavaScript frontend yang dikirim ke browser; karena itu model ini belum melindungi pengguna dari server aktif yang berbahaya.

## Batasan Keamanan Penting

- File export DIPP dan RSA saat ini memuat private key tanpa enkripsi backup.
- Token user/admin berada di `localStorage` dan dapat dibaca JavaScript pada origin aplikasi.
- Private key di RAM belum memiliki timeout otomatis.
- Password masih dikirim ke server melalui TLS; autentikasi belum memakai PAKE seperti OPAQUE/SRP.
- DIPP-KEM adalah algoritma prototipe/custom dan belum boleh dianggap setara KEM standar yang diaudit.
- Root CA key, intermediate CA key, TLS key, database, `server_secret.bin`, dan data runtime pernah terlacak dalam riwayat Git. Material tersebut sudah dikeluarkan dari pelacakan branch produksi, tetapi seluruh secret terkait tetap wajib dirotasi sebelum deployment.
- Rate limit login tersimpan in-memory dan reset saat proses/container restart.
- TLS melindungi data saat transit, bukan dari server/operator yang menyajikan JavaScript berbahaya.

## Deployment Internet

Gunakan `docker-compose.prod.yml` dan Caddy hanya setelah:

1. menetapkan domain dan email ACME;
2. membatasi `ONE_MIND_ALLOWED_HOSTS` ke hostname produksi;
3. memastikan seluruh secret dan data aktif berada di runtime volume/secret storage serta membersihkan riwayat Git lama;
4. merotasi key yang pernah masuk repository;
5. menyiapkan firewall, backup terenkripsi, logging, monitoring, dan rate limiting persisten;
6. memperbaiki export private key agar terenkripsi;
7. mengaktifkan auto-lock key dan mengurangi ketergantungan pada `localStorage` untuk token;
8. melakukan audit kriptografi dan penetration test independen.

Implementasi saat ini adalah prototipe dan belum direkomendasikan untuk data produksi sensitif.

## Prototype Referensi

Kode referensi awal dipertahankan di `Referensi_Awal_Prototype/`. File tersebut bukan entry point aplikasi web saat ini dan tidak boleh digunakan sebagai sumber tunggal perilaku sistem.
