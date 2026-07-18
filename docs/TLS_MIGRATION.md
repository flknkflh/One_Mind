# Deployment TLS ONE_MIND

Dokumen ini mengikuti konfigurasi Docker dan Caddy yang ada pada repository per 18 Juli 2026.

## Dua Mode Deployment

### Lokal atau intranet langsung

`docker-compose.yml` menjalankan aplikasi pada `0.0.0.0:8443`. Uvicorn memuat:

- `/app/certs/server.crt`
- `/app/certs/server.key`

Direktori host yang dipasang:

- `./data:/app/data`
- `./certs:/app/certs`

Jika certificate/key tidak ada, `scripts/entrypoint.sh` menjalankan generator sertifikat self-signed. Akses melalui `https://hostname:8443`.

### Produksi dengan Caddy

`docker-compose.prod.yml` menjalankan:

- aplikasi HTTP internal pada port `8080`;
- Caddy pada port host `80` dan `443`;
- reverse proxy dari domain publik ke `one-mind:8080`.

Uvicorn tidak memakai TLS pada jaringan Docker; Caddy menangani certificate dan HTTPS.

## Persyaratan Produksi

1. Domain mengarah ke IP server.
2. Port 80 dan 443 dapat dicapai Caddy untuk challenge ACME dan trafik HTTPS.
3. Docker/Compose tersedia.
4. DNS, firewall, NAT, dan clock server benar.
5. Email ACME valid.
6. Secret dan data runtime sudah dikeluarkan dari repository.

## Konfigurasi Environment

Buat `.env` berdasarkan `.env.production.example`:

```dotenv
ONE_MIND_DOMAIN=drive.example.com
LETSENCRYPT_EMAIL=admin@example.com
ONE_MIND_ALLOWED_HOSTS=drive.example.com
ONE_MIND_SESSION_SECONDS=43200
ONE_MIND_LOGIN_MAX_FAILURES=8
ONE_MIND_LOGIN_WINDOW_SECONDS=600
```

Jangan memakai `ONE_MIND_ALLOWED_HOSTS=*` pada produksi. Jika aplikasi harus menerima beberapa hostname, gunakan daftar yang memang diperlukan.

## Menjalankan Produksi

```bash
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f caddy
docker compose -f docker-compose.prod.yml logs -f one-mind
```

Uji:

```bash
curl -I https://drive.example.com/
curl https://drive.example.com/health
```

Respons `/health` seharusnya berisi `{"ok":true}`. Pastikan certificate sesuai domain dan tidak ada mixed content.

## Header dan Proxy

Caddy menambahkan HSTS, `nosniff`, frame denial, referrer policy, dan permissions policy. Backend juga menambahkan CSP serta security header. Caddy meneruskan informasi skema sehingga backend dapat memberikan HSTS.

Jangan mengekspos port `8080` aplikasi ke internet. Pada compose produksi port tersebut hanya menggunakan `expose`, bukan mapping host.

## Penyimpanan Produksi

Compose produksi memakai named volume:

- `one_mind_data`: database, storage envelope/ciphertext, upload temporary data, dan server secret;
- `caddy_data`: certificate dan state ACME;
- `caddy_config`: konfigurasi runtime Caddy.

Backup harus mencakup ketiga volume sesuai kebutuhan pemulihan. Backup harus terenkripsi, diuji restore-nya, dan dipisahkan dari host utama.

Private key pengguna tidak ada di volume server menurut implementasi aplikasi; pengguna harus menjaga file DIPP/RSA export masing-masing. Saat ini file export tersebut belum dienkripsi oleh aplikasi.

## Migrasi dari Mode Lokal

1. Hentikan perubahan data atau buat maintenance window.
2. Backup `./data` dan `./certs` secara aman.
3. Audit isi repository dan rotasi secret yang pernah dibagikan.
4. Salin isi data yang diperlukan ke volume `one_mind_data`.
5. Atur domain dan allowed hosts.
6. Jalankan compose produksi.
7. Uji setup/login admin, approval akun, login RSA challenge, certificate, upload chunk, download, share, revoke, update/rotate, dan delete.
8. Verifikasi backup/restore.

Certificate self-signed lokal tidak perlu dipakai Caddy. Jangan menyalin TLS private key development ke deployment publik tanpa alasan dan prosedur rotasi yang jelas.

## Deployment Intranet

Pilihan yang disarankan:

- gunakan CA internal dan certificate yang dipercaya seluruh perangkat organisasi; atau
- gunakan reverse proxy internal dengan certificate perusahaan.

Jika tetap memakai self-signed, distribusikan trust anchor melalui mekanisme administrasi perangkat. Jangan melatih pengguna melewati warning certificate untuk server produksi karena kebiasaan tersebut melemahkan deteksi serangan man-in-the-middle.

Batasi akses dengan firewall/VPN, gunakan hostname tetap, dan set `ONE_MIND_ALLOWED_HOSTS` secara eksplisit.

## Rotasi Certificate dan Secret

- Certificate Caddy umumnya diperbarui otomatis melalui ACME.
- Backup `caddy_data` tetap sensitif karena memuat private key.
- Perubahan `server_secret.bin` membuat seluruh bearer token lama tidak valid.
- Jika root/intermediate CA atau TLS key dalam repo pernah terekspos, lakukan revokasi/rotasi; jangan hanya menghapus filenya.

## Checklist Sebelum Internet

- [ ] Domain dan TLS tervalidasi.
- [ ] Port backend internal tidak terbuka publik.
- [ ] Allowed hosts tidak memakai wildcard.
- [ ] Secret/data aktif tidak terlacak Git.
- [ ] Seluruh key historis yang terekspos sudah dirotasi.
- [ ] Backup terenkripsi dan restore diuji.
- [ ] Monitoring, alert, log retention, dan time synchronization tersedia.
- [ ] Rate limiting eksternal/WAF disiapkan.
- [ ] Batas upload dan kuota ditetapkan.
- [ ] Export private key sudah dienkripsi.
- [ ] Audit aplikasi dan kriptografi selesai.

TLS hanya melindungi data saat transit. TLS tidak membuat implementasi prototipe otomatis aman untuk data sensitif dan tidak melindungi pengguna dari server yang menyajikan JavaScript berbahaya.
