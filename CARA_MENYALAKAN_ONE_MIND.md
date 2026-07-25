# Cara Menyalakan ONE_MIND DIPP

Repo ini adalah varian DIPP dan berjalan berdampingan dengan varian Frodo.

## Jalankan Compose

```powershell
cd "C:\Users\LENOVO\Documents\PELATIHAN_SIBER_3_MINGGU\.AAA_One_Mind_DIPP"
docker compose up -d --build
docker compose ps
```

Container yang diharapkan:

```text
one_mind_dipp
```

Akses DIPP:

```text
https://IP-SERVER:8444
```

Versi Frodo tetap di:

```text
https://172.20.20.154:8443
```

## Uji koneksi

```powershell
Test-NetConnection IP-SERVER -Port 8444
```

Hasil yang diharapkan: `TcpTestSucceeded : True`.

## Firewall Windows

Jalankan sekali dari PowerShell Administrator:

```powershell
New-NetFirewallRule `
  -DisplayName "One Mind DIPP HTTPS 8444" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 8444 `
  -Profile Any
```

Aturan ini tidak dibuat otomatis oleh repo karena membutuhkan hak Administrator.

## Sertifikat

Repo DIPP memakai folder `certs` sendiri. Sertifikat boleh sama dengan Frodo karena hostname/IP sama dan port tidak memengaruhi validitas sertifikat. Jika sertifikat baru dibuat, Root CA terkait harus dipasang lagi di perangkat pengguna.

## Operasi

```powershell
docker compose logs --tail 100
docker compose restart
docker compose down
```

`docker compose down` tidak menghapus folder bind-mount `data` atau `certs`.
