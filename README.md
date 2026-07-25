# ONE_MIND DIPP Ephemeral-R

ONE_MIND DIPP adalah varian penelitian ONE_MIND yang terisolasi dari repo FrodoKEM. Versi ini menerapkan **DIPP Ephemeral-R weighted v2**: setiap akun mempunyai titik privat Bob statis untuk menerima file, sedangkan pengirim membuat 256 titik `R_i` sekali pakai untuk setiap wrapped file key. Isi file tetap dienkripsi di browser dengan AES-256-GCM.

Implementasi mengikuti [spesifikasi integrasi Ephemeral-R](docs/DIPP_EPHEMERAL_R_SPEC_FOR_ONE_MIND.md) dalam mode **standalone pre-key + HKDF**. Tidak ada ECDH atau combiner hybrid. RSA digunakan untuk menandatangani transcript, bukan untuk membentuk shared key.

```text
preKey -> 256 komponen DIPP -> HKDF(transcript) -> K_DIPP
K_DIPP -> AES-256-GCM wrap -> K_AES
```

## Isolasi Compose

- project Compose: `one-mind-dipp`;
- container: `one_mind_dipp`;
- host HTTPS: `8444` (container `8443`);
- database/runtime: `./data` repo DIPP;
- TLS: `./certs` repo DIPP.

Versi Frodo tetap dapat berjalan sebagai project lain pada container `one_mind` dan port `8443`. Port berbeda juga memisahkan origin, token, dan `localStorage` browser.

## Menjalankan

```powershell
cd "C:\Users\LENOVO\Documents\PELATIHAN_SIBER_3_MINGGU\.AAA_One_Mind_DIPP"
docker compose up -d --build
docker compose ps
```

Akses lokal di `https://localhost:8444` atau jaringan di `https://IP-SERVER:8444`. Healthcheck yang benar melaporkan `ONE_MIND_DIPP_EPHEMERAL_R_WEIGHTED_V2` dan container `healthy`.

## Implementasi Ephemeral-R

Saat registrasi browser membuat:

- `seed_A`, public cloud deterministik berukuran `n=16`, dan profil `d=64`;
- titik privat penerima `x_B` serta public transform `B_B`;
- RSA 4096-bit untuk login dan signature transcript;
- vault `.dipp` v8 terenkripsi PBKDF2-SHA-256 600.000 iterasi + AES-256-GCM;
- setiap titik rahasia berbobot 8 dan radiusnya dipilih uniform pada rentang `2S_pub–4S_pub`;
- noise geometrik vector dinonaktifkan pada profil correctness weighted v2; noise modular `e_i ∈ [-64,64]` tetap digunakan.

Untuk setiap pembungkusan, browser membuat pre-key acak 256-bit. Setiap bit memakai `R_i` fresh dan menghasilkan satu `(U_i,V_i)`; `R_i` serta state geometrik sementara kemudian dibersihkan. Pengirim dan penerima menurunkan `K_DIPP` dengan HKDF-SHA-256 menggunakan hash transcript sebagai salt. `K_DIPP` membungkus AES file key memakai AES-256-GCM dengan nonce 12-byte dan AAD terikat transcript.

Tidak ada relay atau syarat peer online. Server hanya menyimpan:

- public identity dan RSA public key;
- ciphertext file serta wrapped key;
- metadata replay minimal pada `dipp_ciphertexts` (`session_id`, identitas, key ID, hash transcript, file context, waktu).

Server memvalidasi schema canonical, parameter, ukuran/dimensi/domain koordinat, `V_i` dalam `Z_q`, komponen duplikat, binding public key penerima, signature pengirim, wrap nonce/ciphertext, dan reuse session/transcript. `x_B`, `R_i`, pre-key, `K_DIPP`, dan plaintext file key tidak disimpan server.

Format ACGR, relay session, DIPP-KEM lama, serta vault sebelum v8 tidak kompatibel dan ditolak.

## Test

```powershell
docker build --target test -t one-mind-dipp-tests .
docker run --rm -e ONE_MIND_DATA_DIR=/tmp/one-mind-dipp-tests one-mind-dipp-tests
node tests/test_dipp_ephemeral_r.js
```

Test JavaScript mencakup SHAKE-256 FIPS 202, public-cloud deterministik, pre-key encapsulation/decapsulation, transcript-bound HKDF, AES-GCM key wrapping, vault, freshness, signature, dan tamper rejection. Test Python mencakup autentikasi transcript, public-material substitution, replay, larangan kolom secret, auth/PKI, chunk ciphertext, serta otorisasi file.

## Data dan database

Runtime berada di `data/`. Database Frodo atau ACGR tidak boleh dipakai karena public identity dan wrapped key tidak kompatibel. Saat skema ini dimulai, tabel relay ACGR `dipp_sessions` dihapus dan diganti registry replay `dipp_ciphertexts`; data file DIPP lama harus dianggap tidak dapat dibuka dengan vault Ephemeral-R.

## Batas keamanan

- Parameter `ER-DIPP-64-16-W8-v2` adalah parameter correctness eksperimen, bukan concrete security parameters.
- Weighting memperlebar distribusi `k_A`, tetapi audit proxy publik `U_i/B_B` masih berhasil jauh di atas peluang acak; profil ini belum membuktikan confidentiality.
- Fixed-point Weiszfeld 24 iterasi belum dilengkapi deterministic curvature certificate produksi.
- Resistance terhadap equivalent-point recovery, prediction, multi-target, chosen-ciphertext, dan serangan kuantum masih harus dianalisis.
- Mode standalone membuat confidentiality bergantung langsung pada asumsi DIPP yang belum tervalidasi; jangan dianggap setara KEM standar atau post-quantum production.
- Token masih berada di `localStorage`; autentikasi password bergantung pada TLS dan belum memakai PAKE.
- Server aktif dapat mengganti JavaScript yang disajikan ke browser.
- Penggunaan untuk data sensitif memerlukan audit kriptografi, penetration test, monitoring, rate limit persisten, backup terenkripsi, dan prosedur rotasi/recovery key.
