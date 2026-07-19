# Deployment ONE_MIND di Jaringan Kantor

Panduan ini menjalankan ONE_MIND hanya pada LAN/Wi-Fi kantor dengan HTTPS
langsung dari Uvicorn pada port `8443`. Konfigurasi ini tidak memakai Caddy,
Let's Encrypt, atau akses internet publik.

Konfigurasi ini tidak mengubah enkripsi file, DIPP, RSA login, atau PKI
certificate pengguna. XCA/CA kantor pada panduan ini hanya menyediakan
identitas TLS untuk server web.

## 1. Siapkan infrastruktur

1. Sediakan satu komputer/server kantor dengan Docker Desktop atau Docker
   Engine dan Compose.
2. Berikan IP statis atau reservasi DHCP, misalnya `192.168.1.20`.
3. Buat DNS internal tetap, misalnya `one-mind.office.local`. Jika kantor belum
   memiliki DNS internal, entri `hosts` dapat dipakai sementara pada perangkat
   uji, bukan sebagai pengelolaan produksi jangka panjang.
4. Sinkronkan waktu server dan klien melalui NTP.
5. Pastikan tidak ada port forwarding/NAT dari internet menuju layanan ini.

## 2. Buat certificate TLS kantor dengan XCA

Buat certificate khusus **TLS server**, bukan certificate pengguna ONE_MIND.
Parameter minimum yang disarankan:

- subject/Common Name: `one-mind.office.local`;
- Subject Alternative Name: `DNS:one-mind.office.local` dan, bila pengguna
  memang mengakses lewat IP, `IP:192.168.1.20`;
- Extended Key Usage: `TLS Web Server Authentication` (`serverAuth`);
- signature: SHA-256 atau lebih kuat;
- masa berlaku mengikuti kebijakan kantor.

Ekspor dari XCA dalam format PEM:

```text
certs/server.crt  # certificate server beserta intermediate chain bila ada
certs/server.key  # private key certificate server
```

Jangan menaruh private key Root CA XCA di server. Distribusikan hanya Root CA
certificate publik ke trust store perangkat kantor menggunakan GPO/MDM atau
mekanisme administrasi resmi. Batasi ACL `server.key` hanya untuk administrator
server dan proses Docker.

File certificate harus sudah tersedia sebelum container kantor dijalankan.
Folder `certs` dipasang read-only sehingga container tidak dapat mengganti key
TLS tersebut. Generator self-signed bawaan hanya cocok untuk development
`localhost`, bukan untuk akses kantor.

## 3. Buat konfigurasi environment

Di PowerShell:

```powershell
Copy-Item .env.office.example .env.office
notepad .env.office
```

Sesuaikan minimal:

```dotenv
ONE_MIND_BIND_IP=192.168.1.20
ONE_MIND_HTTPS_PORT=8443
ONE_MIND_ALLOWED_HOSTS=one-mind.office.local,192.168.1.20
ONE_MIND_PKI_AUTO_INIT=false
```

`ONE_MIND_ALLOWED_HOSTS` tidak boleh `*`. Nilainya tidak memakai `https://`
atau nomor port.

## 4. Siapkan PKI aplikasi

Jika folder `data` yang sekarang sudah berisi PKI aktif dan sudah dirotasi,
gunakan material tersebut tanpa membuat ulang. Untuk instalasi kantor yang
benar-benar baru, bootstrap satu kali dalam maintenance window:

```powershell
docker compose --env-file .env.office -f docker-compose.office.yml run --rm -e ONE_MIND_PKI_AUTO_INIT=true one-mind python -m scripts.bootstrap_pki
```

Sesudah berhasil, pastikan `.env.office` kembali berisi
`ONE_MIND_PKI_AUTO_INIT=false`. Simpan backup terenkripsi material PKI sebelum
membuka layanan. Jangan menjalankan bootstrap untuk menimpa PKI aktif.

## 5. Batasi firewall

Izinkan TCP `${ONE_MIND_HTTPS_PORT}` hanya dari subnet atau VLAN pengguna yang
berhak, misalnya `192.168.1.0/24`. Tolak akses dari guest Wi-Fi, VLAN tamu, dan
interface publik. Aturan firewall host/router harus menjadi kontrol utama;
nilai `ONE_MIND_BIND_IP` memastikan Docker hanya bind pada NIC yang dipilih.

Jika pengguna Wi-Fi tidak saling dipercaya, aktifkan client isolation dan
pastikan hanya koneksi klien-ke-server yang diizinkan. HTTPS mencegah isi
password, token, metadata, wrapped key, dan ciphertext terbaca lewat sniffing,
selama klien mempercayai CA kantor dan tidak mengabaikan warning certificate.

## 6. Validasi dan jalankan

Validasi Compose tanpa mengubah runtime:

```powershell
docker compose --env-file .env.office -f docker-compose.office.yml config --quiet
```

Jalankan layanan:

```powershell
docker compose --env-file .env.office -f docker-compose.office.yml up -d --build
docker compose --env-file .env.office -f docker-compose.office.yml ps
docker compose --env-file .env.office -f docker-compose.office.yml logs --tail 100 one-mind
```

Dari klien yang sudah mempercayai CA kantor, buka:

```text
https://one-mind.office.local:8443
```

Uji health endpoint tanpa melewati validasi certificate:

```powershell
curl.exe --cacert C:\path\ke\office-root-ca.crt https://one-mind.office.local:8443/health
```

Respons yang diharapkan adalah `{"ok":true,...}`. Browser tidak boleh
menampilkan warning certificate. Periksa bahwa SAN certificate cocok dengan
hostname/IP yang dipakai.

## 7. Uji penerimaan kantor

Lakukan pada akun dan file uji sebelum data nyata:

1. setup dan login admin;
2. registrasi, approval, login password, dan RSA proof pengguna;
3. penerbitan serta pembacaan certificate pengguna;
4. upload, download, dekripsi, berbagi, revoke, update, dan delete file;
5. percobaan login gagal dan rate limit;
6. restart container dan verifikasi data tetap ada;
7. akses dari VLAN yang diizinkan dan penolakan dari guest/public network;
8. packet capture untuk memastikan payload aplikasi tidak terlihat sebagai
   plaintext dan hanya trafik TLS yang tampak.

## 8. Backup dan operasi

Backup wajib mencakup:

- seluruh folder `data` (database, ciphertext/envelope, server signing secret,
  dan PKI aplikasi);
- `certs/server.crt` dan `certs/server.key`;
- `.env.office` melalui penyimpanan secret/config yang terlindungi.

Untuk backup konsisten, hentikan layanan dalam maintenance window, salin folder
tersebut ke media backup terenkripsi, lalu jalankan kembali. Uji restore pada
host terpisah. Pantau kapasitas disk, status health container, login gagal,
masa berlaku certificate TLS, dan waktu server.

## Batas keamanan

TLS mengenkripsi data saat transit dan memverifikasi identitas server. TLS tidak
melindungi data jika server/endpoint sudah dikuasai, CA kantor disalahgunakan,
private key TLS bocor, atau pengguna mengabaikan warning browser. Ciphertext
file tetap mengikuti mekanisme enkripsi aplikasi yang sudah ada.
