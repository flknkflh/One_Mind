# Keamanan ONE_MIND

Dokumen ini menjelaskan perilaku kode aktual per 19 Juli 2026, bukan target desain lama.

## Model Keamanan

ONE_MIND melakukan enkripsi isi file di browser. Server menyimpan ciphertext, envelope, metadata, public key, dan wrapped AES key. Pemisahan ini mengurangi paparan plaintext pada server yang jujur, tetapi bukan perlindungan mutlak terhadap operator/server aktif yang berbahaya karena server tetap memasok JavaScript frontend ke browser.

## Transport

- Mode lokal: Uvicorn melayani HTTPS menggunakan `certs/server.crt` dan `certs/server.key`.
- Mode produksi: Uvicorn berjalan HTTP di jaringan Docker dan Caddy melakukan terminasi TLS pada port 443.
- HSTS diberikan pada request HTTPS atau request dengan `X-Forwarded-Proto: https`.
- Password, pending token, bearer token, public key, ciphertext, dan wrapped key melewati jaringan. HTTPS wajib digunakan.

Sertifikat self-signed mengenkripsi trafik tetapi tidak memberi verifikasi identitas yang kuat sebelum certificate dipercaya pengguna. Gunakan CA internal untuk intranet atau CA publik untuk domain internet.

## Header Browser

Backend memasang:

- `Content-Security-Policy` dengan sumber script, style, dan koneksi dibatasi ke origin sendiri;
- `X-Content-Type-Options: nosniff`;
- `X-Frame-Options: DENY`;
- `Referrer-Policy: no-referrer`;
- `Permissions-Policy` yang menonaktifkan camera, microphone, geolocation, dan payment;
- `Cache-Control: no-store` untuk `/` dan `/api/`.

CSP membantu membatasi injeksi, tetapi tidak melindungi dari JavaScript resmi yang sudah dimodifikasi pada server.

## Autentikasi

### Pengguna

1. Password diverifikasi memakai Argon2id pada server. Hash PBKDF2-HMAC-SHA-256 lama dimigrasikan otomatis setelah autentikasi yang valid.
2. Server menerbitkan pending-login token berumur pendek.
3. Browser meminta nonce dan menandatanganinya memakai RSA Login private key.
4. Server memverifikasi RSA signature dan kecocokan public key.
5. Akun harus `ACTIVE` dan certificate harus valid.
6. Server menerbitkan bearer token bertanda tangan HMAC-SHA-256.

Token utama memiliki masa berlaku default 12 jam (`ONE_MIND_SESSION_SECONDS`). Token bukan JWT standar; formatnya adalah payload base64 dan HMAC hex. Tidak ada mekanisme revocation per-token atau daftar sesi server-side. Perubahan status akun diperiksa kembali pada setiap request terautentikasi.

### Administrator

Administrator memakai password dan bearer token terpisah. Token admin juga disimpan di `localStorage`. Setup administrator pertama hanya tersedia ketika tabel administrator masih kosong.

### Rate limit

Percobaan login gagal dibatasi per kombinasi IP dan username. Default delapan kegagalan dalam sepuluh menit. Counter berada di RAM backend sehingga hilang saat restart dan tidak terbagi antar-replica.

## Key di Browser

### DIPP

DIPP private identity diimpor dari file `.dipp` dan disimpan sebagai object JavaScript di RAM tab. DIPP dipakai untuk membuka wrapped AES key. Implementasi saat ini tidak menyimpan DIPP private key di `localStorage`.

### RSA Login

RSA private key diimpor dari file export dan menjadi `CryptoKey` yang bersifat extractable. Key digunakan untuk menandatangani nonce login. Key berada di RAM tab.

### Masa hidup RAM

Auto-lock 15 menit masih dikomentari dalam kode dan belum berfungsi. Key dibersihkan pada logout, refresh/tab ditutup, proses browser berhenti, atau state direset setelah kegagalan tertentu. Selama berada di RAM, key dapat diakses oleh JavaScript origin yang sama dan berpotensi oleh extension/malware.

## Export dan Import Private Key

Perilaku aktual:

- export DIPP menulis public dan private identity ke JSON `.dipp`;
- export RSA menulis private key PKCS#8 base64 dan public key ke JSON;
- tidak ada PBKDF2/AES-GCM yang melindungi file export tersebut;
- import memeriksa tipe dan username, lalu memuat key ke RAM.

File export harus diperlakukan seperti private key plaintext. Jangan mengirimkannya lewat email/chat, jangan menyimpannya bersama password akun, dan simpan dalam media terenkripsi dengan kontrol akses ketat.

Rancangan backup terenkripsi PBKDF2 600.000 iterasi yang disebut dokumentasi lama belum digunakan oleh alur export/import aktual.

## Enkripsi File

- Browser membuat AES-256-GCM key acak per versi file.
- File dienkripsi di browser.
- Ukuran setiap chunk dan SHA-256 seluruh ciphertext diverifikasi server secara incremental sebelum upload diselesaikan.
- Raw AES key diekspor sementara di RAM dan dibungkus untuk setiap penerima menggunakan DIPP-KEM.
- Server menyimpan chunk ciphertext biner, envelope metadata, dan wrapped key, bukan raw AES key.
- Saat update, browser membuat AES key baru dan wrapped key baru untuk semua pengguna yang masih mempunyai akses.

Saat download, server memeriksa record `shares` pada setiap permintaan chunk.
Browser merakit chunk, memeriksa SHA-256, lalu menjalankan verifikasi integritas
AES-GCM saat dekripsi. Chunking menghindari response JSON/Base64 tunggal yang
besar, tetapi ciphertext dan plaintext tetap dapat berada utuh di RAM browser
karena AES-GCM masih diterapkan satu kali untuk seluruh file.

GCM memberi kerahasiaan dan integritas jika nonce tidak digunakan ulang dengan key yang sama. Implementasi membuat key dan IV baru untuk setiap enkripsi.

## Status DIPP-KEM

DIPP-KEM pada repository adalah algoritma custom/prototipe berbasis implementasi referensi proyek. Algoritma ini belum memiliki jaminan keamanan seperti ML-KEM atau skema standar yang melalui standardisasi dan audit luas. Jangan membuat klaim “military-grade”, post-quantum, atau setara FrodoKEM tanpa analisis kriptografi independen.

## Otorisasi File

- `owner`: download, rename, update/rotate, share, revoke, dan delete.
- `editor`: download, rename, dan update/rotate.
- `viewer`: download.

Server memeriksa bearer token dan record `shares`. Pencabutan akses menghentikan request berikutnya, tetapi tidak dapat menarik plaintext atau key lama yang sudah disalin pengguna. Rotasi key melindungi versi berikutnya; ia tidak menghapus salinan historis.

File katalog hanya memaparkan metadata file yang dipilih owner sebagai tidak tersembunyi. Katalog tidak mengirim envelope, ciphertext, atau wrapped key. Permintaan akses tidak memberi hak baca sampai owner menyetujui dan browser owner membuat wrapped key untuk public key peminta. Persetujuan dari alur permintaan selalu menghasilkan permission `viewer`.

## Penyimpanan Browser

`localStorage` memuat token dan username user/admin. Tidak ada cookie `HttpOnly`, `sessionStorage`, atau IndexedDB pada implementasi saat ini. Konsekuensinya, XSS atau JavaScript origin yang berbahaya dapat membaca token.

Data sensitif sementara—password, private key, AES key, plaintext, file import, dan hasil dekripsi—dapat berada di RAM selama operasi.

## Secret dan Data Repository

Riwayat repository memuat material yang tidak semestinya masuk source control:

- root CA private key;
- intermediate CA private key;
- TLS server private key;
- `server_secret.bin`;
- SQLite database aktif;
- envelope/chunk ciphertext aktif;
- backup wrapped key.

Material tersebut sudah dikeluarkan dari pelacakan branch produksi. Jika repository pernah disalin atau dikirim ke remote, tetap anggap secret terekspos. Bersihkan sejarah Git dengan prosedur yang terkontrol, lalu rotasi/revokasi key dan token-signing secret. Menghapus file dari commit terbaru saja tidak membatalkan kebocoran historis.

## Ancaman yang Tidak Ditangani Penuh

- server/operator aktif yang mengganti frontend;
- kompromi endpoint, browser profile, extension, atau malware;
- XSS atau supply-chain compromise;
- pencurian file export private key;
- serangan terhadap algoritma DIPP custom;
- denial of service dan upload berukuran sangat besar;
- distributed brute force melewati rate limit per-process;
- rollback atau penggantian database/storage oleh administrator host;
- keamanan backup di luar aplikasi.

## Prioritas Hardening

1. Rotasi seluruh secret yang pernah masuk Git dan keluarkan data runtime dari repository.
2. Enkripsi file export private key dengan KDF kuat dan authenticated encryption.
3. Aktifkan auto-lock dan nolkan referensi/buffer sensitif sejauh memungkinkan.
4. Pindahkan token dari `localStorage` ke desain sesi cookie `HttpOnly`, `Secure`, `SameSite` dengan proteksi CSRF, atau desain setara.
5. Tambahkan revocation sesi dan rate limit persisten/terdistribusi.
6. Batasi ukuran request, chunk, jumlah upload, dan kuota pengguna.
7. Terapkan build frontend yang ditandatangani/reproducible dan mekanisme verifikasi integritas yang sesuai model ancaman.
8. Ganti/validasi DIPP dengan konstruksi standar setelah review kriptografi.
9. Lakukan dependency scanning, SAST, DAST, penetration test, dan audit akses host.

## Status Produksi

Implementasi saat ini adalah prototipe. Jangan gunakan untuk data pemerintah, militer, kesehatan, finansial, atau data produksi sensitif sebelum hardening dan audit independen selesai.
