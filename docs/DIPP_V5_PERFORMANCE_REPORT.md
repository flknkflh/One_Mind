# DIPP R10S12S Q2500K v5 Performance Report

Tanggal: 17 Agustus 2026

## Profile yang diuji

- Parameter profile: `ER-DIPP-64-16-W8-E2048-R10S12S-Q2500K-v5`
- Radius rahasia: `10S..12S`
- Secret-point weight: `8`
- Quantization scale: `2.500.000`
- Modulus: `65.536`
- Scalar error: `[-2048, 2048]`
- Komponen pre-key: `256`

## Metode

Benchmark menjalankan kode produksi JavaScript dan Web Crypto yang sama dengan
aplikasi. Satu warm-up tidak dihitung, kemudian setiap ukuran diulang tiga kali.
Alurnya:

1. membuat AES-256 file key dan mengenkripsi plaintext dengan AES-GCM;
2. melakukan DIPP encapsulation, HKDF, AES-GCM key wrapping, dan RSA-4096 signature;
3. menulis ciphertext serta envelope ke storage sementara;
4. membaca ciphertext serta envelope kembali;
5. memverifikasi signature, melakukan DIPP decapsulation, HKDF, dan membuka file key;
6. mendekripsi file dan membandingkan SHA-256 plaintext sebelum/sesudah.

Seluruh sembilan putaran menghasilkan plaintext dengan panjang dan SHA-256 yang
sama. Berkas benchmark sementara dihapus setelah setiap putaran.

## Rata-rata hasil

| Ukuran | AES encrypt | DIPP wrap | Tulis disk | Baca disk | DIPP unwrap | AES decrypt | Total |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 MiB | 0,91 ms | 1.101,38 ms | 1,31 ms | 1,13 ms | 632,49 ms | 0,81 ms | 1.738,03 ms |
| 10 MiB | 6,59 ms | 1.109,08 ms | 3,89 ms | 4,60 ms | 632,92 ms | 6,29 ms | 1.763,36 ms |
| 50 MiB | 32,25 ms | 1.112,76 ms | 17,58 ms | 21,00 ms | 637,39 ms | 30,07 ms | 1.851,05 ms |

DIPP wrap relatif konstan sekitar `1,10..1,11 detik` dan unwrap sekitar
`0,63..0,64 detik`, karena DIPP melindungi file key 32 byte dan melakukan 256
operasi komponen terlepas dari ukuran isi file. Waktu AES dan storage bertambah
secara hampir linear terhadap ukuran file.

## Batas pengukuran

- Angka berasal dari runtime Node.js/Web Crypto pada komputer ini, bukan browser
  pengguna lain.
- Storage yang diukur adalah disk lokal sementara, bukan waktu jaringan HTTP,
  latency Wi-Fi, atau chunk upload server.
- Uji browser UI tidak dijalankan karena in-app browser menolak Root CA internal
  dengan `ERR_CERT_AUTHORITY_INVALID`; verifikasi TLS sengaja tidak dilewati.
- Benchmark dapat diulang dengan `node tests/benchmark_dipp_file_flow.js`.

## Status container

Container `one_mind_dipp` berhasil dibangun ulang dan berstatus `healthy` pada
port host `8444`. Endpoint health melaporkan profile
`ONE_MIND_DIPP_EPHEMERAL_R_WEIGHTED_E2048_R10S12S_Q2500K_V5`.
