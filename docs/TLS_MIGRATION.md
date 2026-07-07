# Manual Migrasi TLS: Self-Signed ke Let's Encrypt / Reverse Proxy

Dokumen ini menjelaskan cara memindahkan ONE_MIND dari sertifikat lokal self-signed ke setup profesional memakai reverse proxy dan sertifikat valid, terutama Caddy + Let's Encrypt.

## 1. Kondisi Saat Ini

Mode default lokal memakai:

- container `one_mind`;
- Uvicorn HTTPS langsung di port `8443`;
- sertifikat self-signed di volume `one_mind_certs`;
- akses: `https://localhost:8443`.

Mode ini cocok untuk development, demo lokal, atau intranet kecil yang menerima warning sertifikat.

## 2. Target Produksi

Mode produksi yang disiapkan:

```text
Browser
  |
  | HTTPS valid dari Let's Encrypt
  v
Caddy reverse proxy
  |
  | HTTP internal Docker network
  v
ONE_MIND FastAPI container
```

Pada mode ini:

- Caddy membuka port `80` dan `443`;
- Caddy otomatis meminta dan memperpanjang sertifikat Let's Encrypt;
- aplikasi ONE_MIND berjalan HTTP internal di port `8080`;
- TLS tidak lagi ditangani Uvicorn;
- data tetap di volume `one_mind_data`.

## 3. File yang Disediakan

File baru:

- `docker-compose.prod.yml`: compose produksi dengan Caddy.
- `deploy/Caddyfile`: konfigurasi reverse proxy dan TLS.
- `.env.production.example`: template variabel produksi.

Entrypoint aplikasi mendukung:

- `ONE_MIND_TLS_MODE=internal`: Uvicorn pakai sertifikat internal/self-signed.
- `ONE_MIND_TLS_MODE=off`: Uvicorn HTTP internal untuk reverse proxy TLS.

## 4. Prasyarat Let's Encrypt

Untuk sertifikat Let's Encrypt publik:

1. Punya domain, misalnya `drive.example.com`.
2. DNS `A` record domain mengarah ke IP server.
3. Port `80/tcp` dan `443/tcp` terbuka dari internet ke server.
4. Tidak ada service lain yang memakai port 80/443.
5. Server bisa akses internet untuk ACME challenge.

Jika hanya intranet tertutup tanpa akses internet, gunakan salah satu:

- internal CA perusahaan;
- DNS-01 challenge dengan provider DNS yang didukung Caddy;
- sertifikat manual dari CA internal;
- tetap self-signed, tapi distribusikan root CA ke perangkat user.

## 5. Migrasi dari Local Self-Signed ke Caddy + Let's Encrypt

### 5.1 Backup Dulu

Sebelum migrasi:

```powershell
docker compose stop
docker run --rm --volumes-from one_mind -v "${PWD}:/backup" alpine tar czf /backup/one_mind_before_tls_migration.tar.gz /app/data /app/certs
docker compose up -d
```

Yang paling penting adalah `/app/data`.

### 5.2 Siapkan `.env.production`

Copy template:

```powershell
Copy-Item .env.production.example .env.production
```

Edit:

```text
ONE_MIND_DOMAIN=drive.example.com
LETSENCRYPT_EMAIL=admin@example.com
ONE_MIND_ALLOWED_HOSTS=drive.example.com
ONE_MIND_SESSION_SECONDS=43200
ONE_MIND_LOGIN_MAX_FAILURES=8
ONE_MIND_LOGIN_WINDOW_SECONDS=600
```

Untuk Linux:

```bash
cp .env.production.example .env.production
```

### 5.3 Jalankan Compose Produksi

Stop mode lokal:

```powershell
docker compose down
```

Jalankan mode produksi:

```powershell
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

Caddy akan:

- menerima request HTTP/HTTPS;
- meminta sertifikat Let's Encrypt;
- meneruskan traffic ke `one-mind:8080`.

### 5.4 Verifikasi

Cek container:

```powershell
docker compose --env-file .env.production -f docker-compose.prod.yml ps
```

Cek log Caddy:

```powershell
docker compose --env-file .env.production -f docker-compose.prod.yml logs -f caddy
```

Buka:

```text
https://drive.example.com
```

Browser harus menampilkan sertifikat valid tanpa warning.

## 6. Migrasi Data

Migrasi TLS tidak perlu mengubah data aplikasi.

Yang tetap dipakai:

- `one_mind_data`: database, envelope file, server secret.

Yang tidak wajib dipakai di mode Caddy:

- `one_mind_certs`: sertifikat self-signed lama.

Jika pindah server sekaligus, pindahkan volume data:

```powershell
docker compose stop
docker run --rm --volumes-from one_mind -v "${PWD}:/backup" alpine tar czf /backup/one_mind_data.tar.gz /app/data
```

Restore di server baru:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
docker compose --env-file .env.production -f docker-compose.prod.yml stop one-mind
docker run --rm --volumes-from one_mind -v "$PWD:/backup" alpine sh -c "cd / && tar xzf /backup/one_mind_data.tar.gz"
docker compose --env-file .env.production -f docker-compose.prod.yml up -d
```

## 7. Rollback ke Mode Lokal

Jika produksi gagal:

```powershell
docker compose --env-file .env.production -f docker-compose.prod.yml down
docker compose up -d --build
```

Buka lagi:

```text
https://localhost:8443
```

Data tetap aman selama tidak menjalankan `docker compose down -v`.

## 8. Catatan Reverse Proxy Lain

### 8.1 Nginx

Jika memakai Nginx, konsepnya sama:

- Nginx terminasi TLS di port 443;
- Nginx proxy ke aplikasi HTTP internal;
- set `ONE_MIND_TLS_MODE=off`;
- set `ONE_MIND_PORT=8080`;
- pastikan header `X-Forwarded-Proto: https` dikirim.

Contoh prinsip:

```nginx
location / {
    proxy_pass http://one-mind:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### 8.2 Traefik

Jika memakai Traefik:

- jalankan ONE_MIND dengan `ONE_MIND_TLS_MODE=off`;
- publish service internal port `8080`;
- atur router TLS dan resolver ACME di Traefik.

## 9. Checklist Produksi TLS

- DNS domain sudah mengarah ke server.
- Port 80 dan 443 terbuka.
- `.env.production` sudah benar.
- `ONE_MIND_ALLOWED_HOSTS` tidak memakai `*`.
- Caddy berhasil mendapatkan sertifikat.
- Browser tidak menampilkan warning sertifikat.
- Login, upload, download, share, search, dan rotate key diuji.
- Backup `one_mind_data` sudah dijadwalkan.
- User sudah diberi SOP export/import encrypted private key.

## 10. Kesalahan Umum

### Sertifikat Let's Encrypt gagal dibuat

Kemungkinan:

- DNS belum mengarah ke server;
- port 80/443 tertutup;
- domain masih dipakai reverse proxy lain;
- rate limit Let's Encrypt.

### Aplikasi menolak host

Kemungkinan:

- `ONE_MIND_ALLOWED_HOSTS` belum berisi domain produksi.

Solusi:

```text
ONE_MIND_ALLOWED_HOSTS=drive.example.com
```

Lalu restart compose produksi.

### Browser masih membuka localhost

Gunakan URL domain produksi:

```text
https://drive.example.com
```

Jangan gunakan `https://localhost:8443` saat mode produksi Caddy.
