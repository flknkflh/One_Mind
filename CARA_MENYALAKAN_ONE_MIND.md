# Cara Menyalakan One Mind di Jaringan Wi-Fi

Panduan ini digunakan ketika komputer server dan perangkat pengguna terhubung ke jaringan Wi-Fi yang sama.

## 1. Sambungkan komputer server ke Wi-Fi

Pastikan komputer server dan HP/laptop pengguna memakai jaringan Wi-Fi yang sama.

## 2. Cari alamat IP komputer server

Buka PowerShell, lalu jalankan:

```powershell
ipconfig
```

Cari bagian `Wireless LAN adapter Wi-Fi`, kemudian catat nilai `IPv4 Address`.

Contoh:

```text
IPv4 Address : 172.20.20.154
```

Gunakan `IPv4 Address` komputer server, bukan `Default Gateway`.

## 3. Perbarui konfigurasi `.env`

Buka file `.env` di folder proyek. Masukkan alamat IP komputer server ke `ONE_MIND_ALLOWED_HOSTS`.

Contoh:

```env
ONE_MIND_ALLOWED_HOSTS=localhost,127.0.0.1,one-mind.local,172.20.20.154
```

Jika berpindah ke jaringan baru dan alamat IP berubah, ganti `172.20.20.154` dengan alamat IP yang baru.

Beberapa alamat IP tepercaya dapat dicantumkan sekaligus dan dipisahkan dengan koma:

```env
ONE_MIND_ALLOWED_HOSTS=localhost,127.0.0.1,one-mind.local,172.20.20.154,192.168.1.25
```

Jangan gunakan wildcard `*` untuk pemakaian normal.

## 4. Nyalakan One Mind

Buka PowerShell, lalu masuk ke folder proyek:

```powershell
cd "C:\Users\LENOVO\Documents\PELATIHAN_SIBER_3_MINGGU\.AAA_One_Mind_BUNGKUS"
```

Jalankan One Mind:

```powershell
docker compose up -d
```

Periksa statusnya:

```powershell
docker compose ps
```

Container `one_mind` seharusnya memiliki status `Up`.

Jika kode aplikasi atau Dockerfile baru saja berubah, gunakan:

```powershell
docker compose up -d --build
```

## 5. Uji koneksi di komputer server

Ganti alamat IP pada perintah berikut dengan IP komputer server:

```powershell
Test-NetConnection 172.20.20.154 -Port 8443
```

Hasil yang diharapkan:

```text
TcpTestSucceeded : True
```

## 6. Akses dari perangkat lain

Pada HP atau laptop lain yang tersambung ke Wi-Fi yang sama, buka:

```text
https://172.20.20.154:8443
```

Ganti alamat IP tersebut jika IP komputer server berbeda.

Browser mungkin menampilkan peringatan sertifikat karena One Mind memakai sertifikat internal/self-signed. Untuk jaringan internal yang dipercaya, pilih `Advanced/Lanjutan`, kemudian `Proceed/Lanjutkan`.

## 7. Aturan Windows Firewall

Aturan firewall hanya perlu dibuat satu kali. Buka PowerShell menggunakan **Run as administrator**, lalu jalankan:

```powershell
New-NetFirewallRule `
  -DisplayName "One Mind HTTPS 8443 (Private Wi-Fi)" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 8443 `
  -Profile Any
```

Periksa aturan tersebut:

```powershell
Get-NetFirewallRule `
  -DisplayName "One Mind HTTPS 8443 (Private Wi-Fi)" |
  Select-Object DisplayName, Enabled, Profile, Action
```

Jika aturan sudah ada dengan `Enabled: True`, `Profile: Any`, dan `Action: Allow`, aturan tidak perlu dibuat kembali ketika berpindah Wi-Fi.

## 8. Jika perangkat lain tidak dapat mengakses

Dari laptop Windows lain, jalankan:

```powershell
Test-NetConnection 172.20.20.154 -Port 8443
```

- Jika `TcpTestSucceeded: True`, koneksi jaringan berhasil. Periksa peringatan sertifikat atau pengaturan browser.
- Jika komputer server menghasilkan `True`, tetapi perangkat lain menghasilkan `False`, jaringan kemungkinan memakai AP/client isolation.
- Pastikan kedua perangkat berada pada Wi-Fi yang sama dan alamat IP yang digunakan benar.
- Pada Wi-Fi kantor, kampus, hotel, atau publik, hubungi administrator jaringan jika komunikasi antarpengguna dibatasi.
- Jangan mematikan Windows Firewall secara keseluruhan dan jangan membuka port One Mind ke internet melalui port forwarding.

## 9. Mematikan One Mind

Masuk ke folder proyek, lalu jalankan:

```powershell
docker compose down
```

## Ringkasan setiap berpindah Wi-Fi

1. Sambungkan server dan pengguna ke Wi-Fi yang sama.
2. Jalankan `ipconfig` dan catat `IPv4 Address` server.
3. Masukkan IP baru ke `ONE_MIND_ALLOWED_HOSTS` di `.env`.
4. Jalankan `docker compose up -d`.
5. Uji menggunakan `Test-NetConnection IP-SERVER -Port 8443`.
6. Buka `https://IP-SERVER:8443` dari perangkat lain.

