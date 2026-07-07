# Catatan Keamanan ONE_MIND

## Lapisan Transport

Aplikasi Docker menjalankan Uvicorn dengan `--ssl-certfile` dan `--ssl-keyfile`. Sertifikat dibuat otomatis saat container pertama kali start.

Untuk lokal, sertifikat self-signed cukup untuk mengenkripsi traffic tetapi belum memiliki trust publik. Untuk internet, gunakan sertifikat dari CA publik.

Untuk intranet, tetap jalankan lewat HTTPS/TLS. Self-signed certificate masih melindungi password, token sesi, dan ciphertext metadata dari penyadapan pasif di LAN/Wi-Fi internal. Jika intranet punya internal CA, lebih baik terbitkan sertifikat dari CA internal agar browser user tidak perlu menerima warning manual.

Hardening aplikasi yang aktif:

- header browser security: CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`;
- HSTS saat request lewat HTTPS;
- response HTML/API memakai `Cache-Control: no-store`;
- token sesi punya masa berlaku, default 12 jam via `ONE_MIND_SESSION_SECONDS`;
- percobaan login gagal dibatasi per IP dan username, default 8 kali per 10 menit;
- host header dapat dibatasi dengan `ONE_MIND_ALLOWED_HOSTS`.

Contoh intranet:

```yaml
environment:
  ONE_MIND_ALLOWED_HOSTS: "localhost,127.0.0.1,one-mind.local,192.168.1.20"
  ONE_MIND_SESSION_SECONDS: "43200"
  ONE_MIND_LOGIN_MAX_FAILURES: "8"
  ONE_MIND_LOGIN_WINDOW_SECONDS: "600"
```

Batasi juga dari jaringan:

- buka hanya port yang dipakai aplikasi, default `8443`;
- gunakan firewall server agar hanya subnet intranet/VPN yang boleh masuk;
- hindari expose port aplikasi langsung ke internet;
- jika memakai reverse proxy, proxy harus meneruskan HTTPS sampai client dan mengirim `X-Forwarded-Proto: https`;
- pastikan router, DNS lokal, dan Wi-Fi internal tidak bisa diubah sembarang user.

## Lapisan Data

File dienkripsi di browser memakai AES-256-GCM:

- key acak per file,
- IV 96-bit acak per file,
- AAD berisi metadata nama dan MIME type.

Server hanya menerima envelope berisi IV, AAD, ciphertext, dan metadata.

## Pertukaran Kunci

Versi terpadu ini memakai DIPP-KEM dari prototype `Key_Generator_and_Enkriptor_DIPP_One_Mind_v1.py` untuk lapisan asimetrik:

- saat registrasi, browser membuat `A_points`, `B`, dan parameter publik DIPP;
- private DIPP (`x`, `w`, `delta`) disimpan lokal terenkripsi password;
- saat upload, AES file key dibungkus untuk public DIPP pemilik sendiri;
- saat share, AES file key dibuka lokal lalu dibungkus ulang untuk public DIPP penerima;
- saat download, paket DIPP dibuka memakai private DIPP lokal untuk mendapatkan AES file key.

Isi file tetap memakai AES-256-GCM. DIPP tidak mengenkripsi isi file langsung; DIPP dipakai sebagai lapisan asimetrik untuk pertukaran kunci AES.

## Backup Private Key Browser

Private key user tetap berada di browser, bukan di server. Aplikasi menyediakan export/import encrypted private key untuk pindah perangkat atau browser.

Export:

1. user membuka private key lokal memakai password akun;
2. browser mengenkripsi ulang private key memakai password backup khusus;
3. file `.one-mind-key` dibuat dengan PBKDF2-SHA-256 600.000 iterasi dan AES-256-GCM;
4. user menyimpan file backup dan password backup secara terpisah.

Import:

1. user login di browser baru;
2. user memilih file `.one-mind-key`;
3. browser membuka file memakai password backup;
4. private key disimpan kembali ke localStorage terenkripsi password akun.

File backup tetap sensitif. Siapa pun yang punya file backup dan password backup dapat memulihkan private key user.

## Batasan Saat Ini

- Autentikasi server masih password-over-TLS, belum PAKE.
- Metadata seperti username, filename, owner, ukuran ciphertext, dan waktu upload masih terlihat oleh server.
- Browser localStorage bergantung pada keamanan perangkat user.
- Rate limit login masih in-memory; jika container restart, penghitung percobaan gagal ikut reset.
