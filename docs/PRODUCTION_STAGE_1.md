# Tahap 1: Pemisahan Secret dan Data Runtime

Tahap ini memastikan source code, data pengguna, dan material key tidak lagi
berada dalam satu boundary penyimpanan.

## Perubahan yang diterapkan

- `data/`, `certs/`, database, private key, cache, dan file environment lokal
  diabaikan Git.
- Material Root/Intermediate CA tidak lagi dibaca dari `app/pki`; lokasi default
  barunya adalah `${ONE_MIND_DATA_DIR}/pki`.
- Build context Docker mengecualikan secret dan material PKI lokal.
- File signing secret dan private key baru dibuat dengan permission privat.
- Deployment produksi tidak melakukan bootstrap CA secara diam-diam.

## Bootstrap PKI development

Development menggunakan `ONE_MIND_PKI_AUTO_INIT=true` secara default. PKI juga
dapat dibuat secara eksplisit dengan:

```bash
python -m scripts.bootstrap_pki
```

Lokasi dapat diubah dengan `ONE_MIND_DATA_DIR` atau `ONE_MIND_PKI_DIR`.

## Bootstrap PKI produksi

Produksi menggunakan:

```dotenv
ONE_MIND_PKI_AUTO_INIT=false
```

Sebelum aplikasi produksi dijalankan, provisikan pasangan berikut di volume
data produksi:

```text
pki/root/root_ca.key
pki/root/root_ca.crt
pki/intermediate/intermediate_ca.key
pki/intermediate/intermediate_ca.crt
```

Root CA produksi idealnya disimpan offline. Aplikasi saat ini masih membutuhkan
Intermediate CA private key untuk menerbitkan certificate pengguna; akses file
tersebut harus dibatasi ke proses aplikasi.

Untuk bootstrap awal yang diawasi, `ONE_MIND_PKI_AUTO_INIT` dapat diaktifkan
sementara. Setelah material dibuat dan backup terenkripsi diverifikasi, ubah
kembali menjadi `false` sebelum layanan dibuka.

Dengan Compose produksi dan volume yang masih kosong, bootstrap satu kali dapat
dijalankan melalui:

```bash
docker compose --env-file .env -f docker-compose.prod.yml run --rm \
  -e ONE_MIND_PKI_AUTO_INIT=true one-mind python -m scripts.bootstrap_pki
```

Setelah itu jalankan layanan secara normal dengan
`ONE_MIND_PKI_AUTO_INIT=false`. Jangan menggunakan perintah bootstrap ini untuk
menimpa PKI yang sudah aktif; script akan menolak material pasangan yang tidak
lengkap.

## Rotasi yang masih wajib

Secret dan key lama sudah pernah berada dalam commit Git. Menghentikan tracking
tidak menghapusnya dari riwayat. Sebelum produksi:

1. buat server signing secret produksi baru;
2. buat CA dan TLS key produksi baru;
3. jangan menyalin key dari working tree lama;
4. reissue certificate yang masih bergantung pada CA lama;
5. bersihkan riwayat Git setelah backup dan koordinasi remote;
6. ganti seluruh clone lama setelah history rewrite;
7. uji login, penerbitan certificate, upload, download, dan restore backup.

Perubahan `server_secret.bin` membuat seluruh bearer token lama tidak valid,
tetapi tidak mengubah ciphertext file.
