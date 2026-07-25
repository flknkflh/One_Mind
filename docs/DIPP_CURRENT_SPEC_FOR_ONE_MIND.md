# DIPP Saat Ini untuk Integrasi ONE_MIND

> **Superseded:** dokumen DIPP-ACGR ini hanya arsip desain sebelumnya. Implementasi aktif memakai [DIPP Ephemeral-R standalone pre-key + HKDF](DIPP_EPHEMERAL_R_SPEC_FOR_ONE_MIND.md); ratchet, format vault lama, API relay, dan wrapped key di bawah tidak kompatibel.

**Nama spesifikasi:** DIPP Paired-Endpoint Anti-Correlated Geometric Ratchet  
**Singkatan:** DIPP-ACGR  
**Status:** Draft implementasi penelitian untuk ONE_MIND  
**Versi dokumen:** 1.0  
**Target:** Aplikasi ONE_MIND sebagai penyimpanan dan pertukaran file terenkripsi zero-knowledge

---

## 1. Tujuan Dokumen

Dokumen ini mendeskripsikan bentuk DIPP terbaru yang akan digunakan pada ONE_MIND. Desain ini menggantikan pendekatan DIPP lama yang membungkus 256/512 bit secara terpisah melalui simbol modular berbentuk `m·q/2`.

DIPP terbaru bekerja sebagai **mekanisme pembentukan session key dan ratchet antar-endpoint yang sudah dipasangkan**. Geometric median tetap digunakan sebagai sumber state nonlinear, sedangkan kesamaan key Alice dan Bob diperoleh melalui **anti-correlated modular mask** yang diturunkan dari pairwise root key.

DIPP tidak mengenkripsi file secara langsung. DIPP menghasilkan key pembungkus/session key, sedangkan file tetap dienkripsi menggunakan AES-256-GCM.

Arsitektur utama ONE_MIND menjadi:

```text
PKI / Certificate Enrollment
        ↓
Pembentukan Pairwise Root DIPP
        ↓
DIPP Session + Geometric Ratchet
        ↓
DIPP Session Key / File-Wrapping Key
        ↓
AES-256-GCM untuk file dan metadata sensitif
        ↓
Server hanya menyimpan ciphertext dan public transcript
```

---

## 2. Posisi DIPP di Dalam ONE_MIND

ONE_MIND terdiri atas tiga lapisan utama:

1. **Enrollment dan trust establishment**
   - Menggunakan certificate/PKI pada fase registrasi dan persetujuan admin.
   - PKI memastikan identitas pengguna dan endpoint saat pairing pertama.
   - Setelah pairing berhasil, aktivitas kriptografi sesi menggunakan DIPP.

2. **DIPP paired-endpoint session**
   - Menghasilkan session key yang sama pada dua endpoint.
   - Memasukkan state geometric median ke dalam key dan root-key evolution.
   - Menyediakan session freshness dan ratchet.

3. **AES-256-GCM file protection**
   - Setiap file mempunyai Data Encryption Key atau `K_file` sendiri.
   - `K_file` mengenkripsi file.
   - DIPP menghasilkan `K_wrap` untuk membungkus `K_file`.

Server ONE_MIND tidak boleh menyimpan:

- private DIPP identity;
- pairwise root key;
- secret geometric point;
- file plaintext;
- `K_file` plaintext;
- session key plaintext.

Server hanya menyimpan atau meneruskan:

- ciphertext file;
- nonce dan authentication tag;
- wrapped file key;
- public DIPP messages;
- protocol version;
- transcript hash;
- counter dan routing metadata minimum.

---

## 3. Perubahan dari DIPP Lama

### 3.1 DIPP lama

DIPP lama menggunakan banyak instance independen dan membungkus bit satu per satu:

```text
V_i = Z_i + m_i·q/2 + e_i mod q
```

Masalah yang ditemukan:

- ciphertext dapat menjadi verifier untuk candidate shared value;
- attacker dapat menguji kandidat terhadap pusat `0` dan `q/2`;
- jumlah ciphertext meningkat sesuai jumlah bit;
- correctness bergantung pada reconciliation margin per bit;
- equivalent-candidate attack tidak harus menemukan secret asli.

### 3.2 DIPP terbaru

DIPP terbaru tidak mengirim 256 simbol `q/2`. Kedua pihak membentuk satu raw shared vector:

```text
K_raw ∈ Z_q^d
```

Kemudian satu session key 256 bit diturunkan melalui HKDF:

```text
SK_t = HKDF(root_t || K_raw || transcript_hash)
```

Keuntungan struktural:

- tidak ada candidate verifier per bit;
- raw agreement exact pada profil utama;
- satu key diturunkan dari seluruh vector;
- session key dan root berikutnya menggunakan domain separation;
- state geometry dicampurkan ke setiap transisi ratchet.

Implementasi ONE_MIND harus menolak format DIPP lama pada modul baru. Format lama dapat dipertahankan hanya untuk migrasi data terkontrol, bukan untuk sesi baru.

---

## 4. Model Sistem

Dua endpoint disebut Alice dan Bob.

Pada awal sesi ke-`t`, keduanya mempunyai state rahasia pasangan yang sama:

```text
κ_t = pairwise root key 256 bit
```

State ini diperoleh saat authenticated pairing dan disimpan di dalam vault `.dipp` terenkripsi. Sesuai model ONE_MIND:

- state tidak disimpan pada server;
- state tidak disimpan sebagai JavaScript constant;
- state tidak disimpan permanen dalam bentuk plaintext di browser;
- state dimuat ke RAM hanya setelah pengguna membuka vault DIPP;
- state lama dihapus setelah ratchet berhasil dikonfirmasi.

### 4.1 Threat model

Attacker boleh:

- membaca seluruh lalu lintas jaringan;
- menyimpan public transcript;
- mengirim ulang pesan lama;
- mengubah, menunda, menghapus, atau menyisipkan pesan;
- menguasai server penyimpanan;
- menjalankan candidate search berdasarkan public geometry.

Attacker diasumsikan tidak dapat:

- membaca pairwise root dari RAM endpoint yang sehat;
- membaca secret geometric point dari endpoint yang sehat;
- memalsukan authentication tag tanpa key;
- mengeksekusi arbitrary code di endpoint tanpa dianggap endpoint compromise.

Endpoint compromise, recovery, dan post-compromise security harus dianalisis sebagai bagian terpisah.

---

## 5. Notasi dan Parameter

| Simbol | Makna |
|---|---|
| `A_t` | public point cloud untuk sesi `t` |
| `d` | dimensi geometric vector |
| `n` | jumlah public points |
| `x_A`, `x_B` | secret point lokal Alice dan Bob |
| `P_A`, `P_B` | clean geometric median real-valued |
| `p_A`, `p_B` | geometric median setelah fixed-point quantization |
| `q` | modulus vector |
| `s` | fixed-point scale |
| `κ_t` | pairwise root key sesi saat ini |
| `r_t` | anti-correlated mask vector |
| `B_A`, `B_B` | public DIPP values |
| `K_raw` | raw shared vector |
| `SK_t` | final DIPP session key |
| `κ_(t+1)` | pairwise root sesudah ratchet |
| `T_t` | canonical session transcript |
| `ν_A`, `ν_B` | residual implementation opsional |

### 5.1 Profil penelitian awal

Parameter demo yang sudah digunakan:

```text
Dimension d       : 16, 32, 64, 128
Public points n   : 8
Modulus q         : 2^31 - 1
Fixed scale s     : 1000
Root key          : 256 bit
Session key       : 256 bit
Hash/HMAC/HKDF    : SHA-256 family
File encryption   : AES-256-GCM
```

Nilai tersebut adalah profil penelitian dan demo. Penetapan parameter produksi memerlukan benchmark, fixed-point validation, cryptanalysis, dan security target yang eksplisit.

---

## 6. Canonical Session Context

Semua input publik sesi harus diserialisasi secara canonical.

```text
context_t = EncodeCanonical({
    protocol: "ONE_MIND_DIPP_ACGR",
    version: 1,
    pair_id: pairId,
    alice_id: aliceId,
    bob_id: bobId,
    counter: t,
    nonce_alice: nA,
    nonce_bob: nB,
    geometry_seed: geometrySeed,
    dimension: d,
    public_point_count: n,
    modulus: q,
    fixed_scale: s
})
```

Hash context:

```text
context_hash = SHA-256(context_t)
```

Context wajib mengikat:

- protocol name;
- protocol version;
- pair identity;
- role Alice/Bob;
- monotone session counter;
- fresh nonce kedua endpoint;
- geometry seed;
- parameter set identifier.

Tujuannya mencegah:

- replay lintas sesi;
- reflection Alice ↔ Bob;
- cross-protocol reuse;
- penggunaan geometry dari sesi berbeda;
- parameter downgrade.

---

## 7. Pembentukan Public Geometry

Public point cloud diturunkan secara deterministik dari context:

```text
A_t = DerivePublicPoints(
    SHAKE-256("DIPP-GEOMETRY" || context_hash),
    dimension = d,
    count = n,
    coordinate_bound = C
)
```

Kedua endpoint harus memperoleh point cloud yang identik bit-per-bit.

Rejection sampling disarankan agar distribusi koordinat tidak bias akibat modular reduction.

Contoh bentuk:

```text
A_t = {a_1, a_2, ..., a_n},  a_i ∈ Z^d
```

Public geometry bukan secret. Security tidak boleh bergantung pada menyembunyikan `A_t`.

---

## 8. Secret Geometric State

Setiap endpoint mempunyai secret geometric point:

```text
x_A ∈ Z^d
x_B ∈ Z^d
```

Secret point dapat:

- diturunkan dari protected DIPP identity dan context;
- atau dibangkitkan fresh per sesi menggunakan CSPRNG.

Untuk deterministic ratchet dan test vector, bentuk yang disarankan:

```text
x_A = MapToSecretPoint(
    HKDF(κ_t, context_hash, "DIPP-ALICE-SECRET-POINT")
)

x_B = MapToSecretPoint(
    HKDF(κ_t, context_hash, "DIPP-BOB-SECRET-POINT")
)
```

Role label harus berbeda agar Alice dan Bob tidak memperoleh point identik secara tidak sengaja.

Alternatif fresh local randomness boleh digunakan, tetapi membutuhkan aturan transcript dan recovery yang lebih kompleks.

---

## 9. Geometric Median

Untuk kumpulan point dengan positive weights:

```text
GM(Y, w) = argmin_z Σ_i w_i · ||z - y_i||_2
```

Alice menghitung:

```text
P_A = GM(A_t ∪ {x_A})
```

Bob menghitung:

```text
P_B = GM(A_t ∪ {x_B})
```

Weighted profile dapat digunakan:

```text
P_A = GM(A_t ∪ {x_A}, {u_1, ..., u_n, w_A})
P_B = GM(A_t ∪ {x_B}, {u_1, ..., u_n, w_B})
```

Semua weights harus positif dan berada dalam parameter profile yang divalidasi.

### 9.1 Weiszfeld iteration

Untuk iterate `z_k`:

```text
z_(k+1) =
    [Σ_i w_i y_i / ||y_i - z_k||]
    --------------------------------
    [Σ_i w_i / ||y_i - z_k||]
```

Implementasi harus menangani kondisi ketika iterate sangat dekat dengan salah satu input point.

### 9.2 Production requirement

Implementasi produksi sebaiknya:

- menggunakan fixed-point/integer arithmetic;
- mempunyai iteration cap tetap;
- mempunyai convergence threshold yang ditetapkan;
- mempunyai singular-point handling;
- menghasilkan solver residual untuk diagnostic/certificate;
- tidak menggunakan data-dependent early exit jika timing leakage menjadi perhatian.

---

## 10. Quantization

Real-valued center dipetakan ke modular integer vector:

```text
Q_s(P) = round(s · P) mod q
```

Alice:

```text
p_A = Q_s(P_A)
```

Bob:

```text
p_B = Q_s(P_B)
```

Nearest-integer quantization memberi bound per koordinat:

```text
|Q_s(P)_j / s - P_j| ≤ 1 / (2s)
```

Canonical integer encoding harus menentukan:

- signed/centered representation;
- byte order;
- fixed byte width;
- rejection terhadap coordinate di luar range;
- larangan multiple encodings untuk nilai yang sama.

---

## 11. Derivasi Anti-Correlated Mask

Kedua endpoint menghitung mask seed yang sama:

```text
mask_seed = HKDF-SHA-256(
    ikm  = κ_t,
    salt = context_hash,
    info = "ONE_MIND-DIPP-MASK-SEED-v1",
    length = 32
)
```

Mask vector:

```text
r_t = MapToVector(
    SHAKE-256(mask_seed || context_hash),
    dimension = d,
    modulus = q
)
```

Alice menggunakan `+r_t`; Bob menggunakan `-r_t`.

Aturan tanda bersifat publik. Nilai `r_t` tetap rahasia karena diturunkan dari `κ_t`.

Mask harus:

- fresh untuk setiap context;
- tidak digunakan ulang;
- tidak dikirim;
- tidak dicatat ke log;
- dihapus dari RAM setelah ratchet selesai.

---

## 12. Public DIPP Values

Alice membentuk:

```text
B_A = p_A + r_t mod q
```

Bob membentuk:

```text
B_B = p_B - r_t mod q
```

Pesan publik minimal:

```json
{
  "type": "ONE_MIND_DIPP_PUBLIC_VALUE",
  "version": 1,
  "pair_id": "...",
  "session_id": "...",
  "counter": 42,
  "role": "alice",
  "context_hash": "base64url(...) ",
  "vector": "base64url(canonical_integer_vector)",
  "auth_tag": "base64url(...)"
}
```

`auth_tag` harus diturunkan dari key terpisah:

```text
auth_key = HKDF(κ_t, context_hash, "ONE_MIND-DIPP-HANDSHAKE-AUTH-v1")
auth_tag = HMAC-SHA-256(auth_key, canonical_message_without_auth_tag)
```

PKI tidak perlu digunakan untuk menandatangani setiap sesi setelah pairing, karena DIPP root menyediakan session authentication. Certificate tetap menjadi dasar enrollment dan identity approval.

---

## 13. Raw Shared Vector

Setelah menerima dan memvalidasi peer public value:

Alice menghitung:

```text
K_A_raw = p_A - B_B mod q
```

Bob menghitung:

```text
K_B_raw = B_A - p_B mod q
```

Substitusi:

```text
K_A_raw
= p_A - (p_B - r_t)
= p_A - p_B + r_t mod q
```

```text
K_B_raw
= (p_A + r_t) - p_B
= p_A - p_B + r_t mod q
```

Maka:

```text
K_A_raw = K_B_raw
```

Ini adalah identitas exact dan tidak bergantung pada `p_A ≈ p_B`.

Geometric centers boleh berbeda jauh. Agreement diperoleh dari struktur modular anti-correlation.

---

## 14. Ringkasan Pembuktian Correctness

### Theorem 1 — Convex-hull boundedness

Setiap geometric median dari positively weighted finite point set berada di dalam convex hull input points.

Jika seluruh point berada di box:

```text
[-C, C]^d
```

maka:

```text
||P_A||_∞ ≤ C
||P_B||_∞ ≤ C
```

Setelah scaling:

```text
||round(sP_A)||_∞ ≤ sC + 1/2
||round(sP_B)||_∞ ≤ sC + 1/2
```

### Theorem 2 — Quantization bound

Untuk setiap koordinat:

```text
|round(sP_j)/s - P_j| ≤ 1/(2s)
```

### Theorem 3 — Exact DIPP agreement

Dengan:

```text
B_A = p_A + r_t mod q
B_B = p_B - r_t mod q
```

maka:

```text
K_A_raw = p_A - B_B
K_B_raw = B_A - p_B
```

menghasilkan:

```text
K_A_raw = K_B_raw = p_A - p_B + r_t mod q
```

### Theorem 4 — Bounded residual disagreement

Untuk implementasi generalized:

```text
B_A = p_A + r_t + ν_A mod q
B_B = p_B - r_t + ν_B mod q
```

maka:

```text
K_A_raw - K_B_raw = -(ν_A + ν_B) mod q
```

Jika:

```text
||ctr(ν_A + ν_B)||_∞ ≤ β < q/2
```

maka:

```text
||ctr(K_A_raw - K_B_raw)||_∞ ≤ β
```

Profil utama ONE_MIND harus menggunakan:

```text
ν_A = ν_B = 0
```

sehingga raw agreement exact.

### Theorem 5 — Final key equality

Jika Alice dan Bob mempunyai:

- root `κ_t` yang sama;
- canonical transcript yang sama;
- `K_raw` yang sama;
- deterministic serialization yang sama;

maka kedua endpoint memberi input byte-identik ke HKDF dan menghasilkan:

```text
SK_A_t = SK_B_t
κ_A_(t+1) = κ_B_(t+1)
```

---

## 15. Session Key dan Root Ratchet

Canonical transcript:

```text
T_t = context_t || Encode(B_A) || Encode(B_B)
T_hash = SHA-256(T_t)
```

Session key:

```text
SK_t = HKDF-SHA-256(
    ikm = κ_t || Encode(K_raw) || T_hash,
    salt = SHA-256(T_hash || "key-salt"),
    info = "ONE_MIND-DIPP-SESSION-KEY-v1",
    length = 32
)
```

Root berikutnya:

```text
κ_(t+1) = HKDF-SHA-256(
    ikm = κ_t || Encode(K_raw) || T_hash,
    salt = SHA-256(T_hash || "ratchet-salt"),
    info = "ONE_MIND-DIPP-ROOT-UPDATE-v1",
    length = 32
)
```

Key untuk handshake authentication, file-key wrapping, dan root update harus memakai label berbeda.

Dilarang menggunakan satu hasil HKDF langsung untuk seluruh fungsi.

---

## 16. Two-Phase Ratchet Commit

Root tidak boleh langsung diganti saat public value dikirim. Gunakan state transition:

```text
ACTIVE κ_t
    ↓ derive
PENDING κ_(t+1)
    ↓ authenticated confirmation
COMMITTED κ_(t+1)
    ↓ erase
DELETE κ_t
```

### 16.1 Alice

1. Membuat `B_A`.
2. Menerima dan memvalidasi `B_B`.
3. Menghitung `SK_t` dan pending root.
4. Mengirim confirmation MAC.
5. Menunggu Bob confirmation.
6. Commit pending root.
7. Menghapus old root dan transient state.

### 16.2 Bob

Urutan simetris.

Jika timeout atau confirmation gagal:

- jangan commit root baru;
- hapus pending state;
- session dianggap gagal;
- counter yang gagal dicatat untuk mencegah replay ambiguity.

---

## 17. Integrasi dengan Enkripsi File ONE_MIND

DIPP menghasilkan session key, bukan menggantikan AES file encryption.

### 17.1 File encryption

Untuk setiap file:

```text
K_file  ← CSPRNG(32 bytes)
N_file  ← CSPRNG(12 bytes)
C_file, Tag_file = AES-256-GCM-Encrypt(
    key = K_file,
    nonce = N_file,
    plaintext = file_bytes,
    aad = canonical_file_metadata
)
```

### 17.2 File-key wrapping

Turunkan wrapping key:

```text
K_wrap = HKDF-SHA-256(
    ikm = SK_t,
    salt = file_id_hash,
    info = "ONE_MIND-DIPP-FILE-KEY-WRAP-v1",
    length = 32
)
```

Wrap `K_file`:

```text
N_wrap ← CSPRNG(12 bytes)
C_key, Tag_key = AES-256-GCM-Encrypt(
    key = K_wrap,
    nonce = N_wrap,
    plaintext = K_file,
    aad = file_id || sender_id || receiver_id || transcript_hash
)
```

Upload ke server:

```json
{
  "file_id": "...",
  "owner_id": "...",
  "receiver_id": "...",
  "ciphertext_file": "...",
  "file_nonce": "...",
  "file_tag": "...",
  "wrapped_file_key": "...",
  "wrap_nonce": "...",
  "wrap_tag": "...",
  "dipp_transcript_hash": "...",
  "protocol_version": "ONE_MIND_DIPP_ACGR_V1"
}
```

Server tidak mengetahui `K_file`, `K_wrap`, atau `SK_t`.

### 17.3 File decryption

Receiver:

1. Menyelesaikan/menemukan DIPP session yang sesuai.
2. Menghasilkan `SK_t`.
3. Menurunkan `K_wrap`.
4. Membuka wrapped `K_file`.
5. Mendekripsi file dengan AES-256-GCM.
6. Menolak file jika salah satu GCM tag gagal.

---

## 18. Mode Operasi yang Didukung

### 18.1 Synchronous paired session

Didukung oleh desain saat ini.

```text
Alice online ↔ server relay ↔ Bob online
```

Kedua endpoint melakukan handshake DIPP dan menurunkan session key pada waktu yang sama.

### 18.2 Persistent paired channel

Didukung melalui root ratchet berurutan.

```text
κ_0 → κ_1 → κ_2 → ...
```

Setiap sesi menghasilkan root baru.

### 18.3 Asynchronous file delivery

Belum lengkap pada desain inti ini. Receiver yang offline memerlukan salah satu mekanisme tambahan:

- DIPP prekey batch;
- queued session envelope;
- sealed pairwise state;
- asynchronous ratchet extension.

Mekanisme tersebut harus didesain dan dianalisis terpisah sebelum dipakai. Jangan menyamakan synchronous DIPP handshake dengan offline KEM.

---

## 19. Data Structure yang Disarankan

### 19.1 DIPP identity vault

Vault `.dipp` harus dienkripsi menggunakan password-derived key atau device-bound protection.

```json
{
  "version": 5,
  "type": "ONE_MIND_DIPP_ACGR_IDENTITY",
  "user_id": "user-uuid",
  "created_at": "ISO-8601",
  "identity_secret": "encrypted-base64url",
  "pairs": [
    {
      "pair_id": "pair-uuid",
      "peer_user_id": "peer-uuid",
      "root_key": "encrypted-base64url",
      "send_counter": 12,
      "receive_counter": 12,
      "last_transcript_hash": "base64url",
      "state": "active"
    }
  ]
}
```

Jangan simpan `root_key` plaintext dalam JSON.

### 19.2 Runtime state

```ts
interface DippRuntimePairState {
  pairId: string;
  localUserId: string;
  peerUserId: string;
  rootKey: Uint8Array;       // RAM only
  sendCounter: bigint;
  receiveCounter: bigint;
  pending?: PendingRatchet;
}
```

### 19.3 Pending session

```ts
interface PendingRatchet {
  sessionId: string;
  counter: bigint;
  contextHash: Uint8Array;
  localPublicValue: Uint8Array;
  peerPublicValue?: Uint8Array;
  sessionKey?: Uint8Array;
  nextRoot?: Uint8Array;
  transcriptHash?: Uint8Array;
  status: "created" | "peer_received" | "confirmed";
}
```

---

## 20. Modul Implementasi

Struktur modul yang disarankan:

```text
src/
├── dipp/
│   ├── constants.ts
│   ├── canonical_encoding.ts
│   ├── context.ts
│   ├── geometry.ts
│   ├── geometric_median.ts
│   ├── quantization.ts
│   ├── vector_mod_q.ts
│   ├── mask_derivation.ts
│   ├── handshake_auth.ts
│   ├── session.ts
│   ├── ratchet.ts
│   ├── validation.ts
│   ├── test_vectors.ts
│   └── legacy_reject.ts
├── crypto/
│   ├── hkdf.ts
│   ├── hmac.ts
│   ├── aes_gcm.ts
│   ├── file_encryption.ts
│   └── secure_erase.ts
├── identity/
│   ├── dipp_vault.ts
│   ├── certificate_enrollment.ts
│   └── pair_state.ts
└── network/
    ├── dipp_relay.ts
    ├── upload_ciphertext.ts
    └── download_ciphertext.ts
```

---

## 21. Pseudocode Protokol

### 21.1 Alice start

```text
function AliceStart(pairState, peerId):
    κ_t       = pairState.root
    counter   = pairState.sendCounter + 1
    n_A       = RandomBytes(32)

    send INIT(pairId, counter, n_A, parameterSetId)
```

### 21.2 Bob response

```text
function BobRespond(pairState, initMessage):
    ValidateCounter(initMessage.counter)

    n_B          = RandomBytes(32)
    context      = BuildContext(initMessage, n_B)
    contextHash  = Hash(context)
    A_t          = DerivePublicPoints(contextHash)
    x_B          = DeriveSecretPoint(pairState.root, contextHash, "BOB")
    P_B          = GeometricMedian(A_t, x_B)
    p_B          = Quantize(P_B)
    r_t          = DeriveMask(pairState.root, contextHash)
    B_B          = ModQ(p_B - r_t)
    authTag      = AuthenticateHandshake(pairState.root, contextHash, B_B)

    save pending state
    send RESPONSE(n_B, B_B, authTag)
```

### 21.3 Alice public value and derivation

```text
function AliceComplete(pairState, initState, response):
    context      = BuildContext(initState, response.n_B)
    contextHash  = Hash(context)
    VerifyAuthTag(response)

    A_t          = DerivePublicPoints(contextHash)
    x_A          = DeriveSecretPoint(pairState.root, contextHash, "ALICE")
    P_A          = GeometricMedian(A_t, x_A)
    p_A          = Quantize(P_A)
    r_t          = DeriveMask(pairState.root, contextHash)
    B_A          = ModQ(p_A + r_t)

    K_raw        = ModQ(p_A - response.B_B)
    transcript   = Canonical(context, B_A, response.B_B)
    SK_t         = DeriveSessionKey(pairState.root, K_raw, transcript)
    nextRoot     = DeriveNextRoot(pairState.root, K_raw, transcript)

    authTag      = AuthenticateHandshake(pairState.root, Hash(transcript), B_A)
    save pending root
    send FINAL(B_A, authTag, confirmationMac)
```

### 21.4 Bob final derivation

```text
function BobComplete(pairState, pending, finalMessage):
    VerifyAuthTag(finalMessage)

    K_raw       = ModQ(finalMessage.B_A - pending.p_B)
    transcript  = Canonical(pending.context, finalMessage.B_A, pending.B_B)
    SK_t        = DeriveSessionKey(pairState.root, K_raw, transcript)
    nextRoot    = DeriveNextRoot(pairState.root, K_raw, transcript)

    verify confirmation
    send confirmation
    commit nextRoot after mutual confirmation
```

---

## 22. Validation Rules

Endpoint wajib menolak pesan jika:

- protocol/version tidak dikenal;
- pair ID tidak cocok;
- identity role terbalik;
- counter lama atau sudah pernah digunakan;
- nonce length salah;
- context hash tidak cocok;
- vector dimension salah;
- coordinate encoding tidak canonical;
- coordinate berada di luar `[0, q-1]`;
- auth tag salah;
- duplicate session ID;
- transcript berubah setelah confirmation;
- parameter set tidak disetujui;
- message DIPP legacy digunakan pada endpoint vNext.

Seluruh comparison untuk authentication tags harus constant-time.

---

## 23. Server API Minimum

Server berfungsi sebagai relay dan zero-knowledge storage.

### Handshake relay

```text
POST /api/dipp/sessions/init
POST /api/dipp/sessions/respond
POST /api/dipp/sessions/final
POST /api/dipp/sessions/confirm
GET  /api/dipp/sessions/pending
```

### File storage

```text
POST /api/files/upload-encrypted
GET  /api/files/:id/envelope
GET  /api/files/:id/ciphertext
DELETE /api/files/:id
```

Server memvalidasi schema, authorization, size, dan routing, tetapi tidak melakukan geometric computation atau key derivation.

---

## 24. Security Properties yang Dituju

### 24.1 Exact raw agreement

Pada profil `ν_A = ν_B = 0`:

```text
K_A_raw = K_B_raw
```

### 24.2 Session freshness

Mask dan key mengikat fresh nonces, counter, geometry, dan transcript.

### 24.3 Replay resistance

Counter dan transcript binding membuat public value sesi lama tidak valid pada sesi baru.

### 24.4 Server zero knowledge

Server tidak mempunyai root, secret point, session key, atau file key.

### 24.5 Candidate separation

Candidate geometric point saja tidak cukup untuk menghitung final key karena HKDF dan mask bergantung pada root rahasia.

### 24.6 Ratchet

Root berubah setelah setiap sesi berhasil.

---

## 25. Security Claim Boundary

Desain saat ini dapat menyatakan:

- geometric state mempunyai deterministic boundedness jika input bounded;
- quantization error dapat dibatasi;
- raw agreement exact pada profil utama;
- residual disagreement mempunyai bound eksplisit;
- final key sama jika root dan transcript sama;
- transcript-only candidate tidak memiliki keyed extractor tanpa root, berdasarkan asumsi HMAC/HKDF.

Desain saat ini belum boleh menyatakan:

- native geometric median problem terbukti LWE-hard;
- DIPP merupakan pengganti langsung standardized public-key KEM;
- DIPP sudah IND-CCA secure;
- DIPP sudah mendapat classical/quantum security level tertentu;
- server compromise tidak berpengaruh jika endpoint atau vault ikut bocor;
- asynchronous file delivery sudah selesai tanpa prekey extension.

Untuk penulisan akademik, gunakan istilah:

```text
post-quantum-oriented paired-endpoint key-establishment and ratchet framework
```

bukan:

```text
proven post-quantum public-key KEM
```

---

## 26. Simulasi yang Sudah Dijalankan

Simulasi penelitian menjalankan:

```text
Dimension            : 16, 32, 64, 128
Sessions/dimension   : 300
Total sessions       : 1,200
```

Hasil:

```text
Raw vector agreement       : 100%
Final session-key agreement: 100%
Maximum coordinate gap     : 0
Public candidate exact key : 0 / 1,200
Wrong-root exact key       : 0 / 1,200
Public candidate HD        : approximately 50.016%
Wrong-root HD              : approximately 50.072%
```

Interpretasi yang benar:

- hasil membuktikan implementasi simulasi mengikuti exact identity;
- hasil menunjukkan candidate baseline menghasilkan key tidak berkorelasi pada sampel tersebut;
- hasil tidak menggantikan formal authenticated-key-exchange proof;
- jumlah trial tidak membuktikan batas serangan kriptografi produksi.

---

## 27. Test Plan ONE_MIND

### 27.1 Unit tests

- canonical encoding;
- modular add/subtract;
- centered representation;
- geometry derivation deterministic;
- secret-point derivation role-separated;
- Weiszfeld known examples;
- quantization boundary;
- mask derivation deterministic;
- exact raw identity;
- HKDF domain separation;
- AES-GCM wrap/unwrap;
- legacy format rejection.

### 27.2 Cross-platform tests

Jalankan test vector yang sama pada:

- Chromium/Chrome;
- Firefox;
- Edge;
- Node.js reference;
- Windows dan Linux.

Seluruh output berikut harus identik:

- context bytes;
- context hash;
- public point cloud;
- quantized centers;
- `B_A`, `B_B`;
- `K_raw`;
- transcript hash;
- session key;
- next root.

Floating-point geometric median berisiko berbeda antar-platform. Karena itu test produksi harus beralih ke fixed-point.

### 27.3 Negative tests

- modified `B_A`;
- modified `B_B`;
- wrong root;
- wrong role;
- wrong counter;
- reused nonce;
- changed geometry seed;
- changed dimension;
- malformed vector;
- noncanonical encoding;
- failed confirmation;
- duplicated final message;
- stale session;
- server reordering messages.

### 27.4 Multi-session tests

- 10,000 sequential ratchets;
- interruption before commit;
- interruption after one-sided commit;
- duplicate confirmation;
- recovery from pending state;
- old root erasure check;
- concurrency on two sessions for the same pair.

---

## 28. Implementation Priority

Urutan implementasi di ONE_MIND:

1. Canonical binary encoder.
2. Modular vector library.
3. Deterministic public geometry.
4. Fixed-point geometric median.
5. Quantization.
6. Pairwise-root vault loading into RAM.
7. Mask and authentication-key derivation.
8. DIPP handshake relay.
9. Exact raw-vector test.
10. Session-key and root derivation.
11. Two-phase ratchet commit.
12. AES file-key wrapping.
13. Encrypted file upload/download.
14. Negative and replay tests.
15. Asynchronous extension only after synchronous mode stabilizes.

---

## 29. Definition of Done

DIPP vNext untuk ONE_MIND dianggap siap pada tahap aplikasi penelitian ketika:

- seluruh 1,000+ deterministic cross-platform test vectors cocok;
- exact `K_raw` equality tercapai pada seluruh honest sessions;
- tampered transcript selalu ditolak;
- wrong-root selalu gagal membuka wrapped file key;
- server database tidak memiliki secret material;
- old root dihapus setelah successful confirmation;
- failed session tidak menyebabkan permanent ratchet divergence;
- file encryption dan key wrapping memakai nonce unik;
- semua legacy DIPP messages ditolak oleh endpoint baru;
- notebook/demo dan aplikasi menghasilkan output identik untuk test vector yang sama.

---

## 30. Ringkasan Akhir

DIPP terbaru pada ONE_MIND bukan lagi bitwise geometric reconciliation. DIPP sekarang merupakan **paired-endpoint geometric key ratchet**.

Inti protokol:

```text
P_A = GM(A_t, x_A)
p_A = Quantize(P_A)

P_B = GM(A_t, x_B)
p_B = Quantize(P_B)

r_t = PRF(κ_t, context_t)

B_A = p_A + r_t mod q
B_B = p_B - r_t mod q

K_A_raw = p_A - B_B mod q
K_B_raw = B_A - p_B mod q

K_A_raw = K_B_raw = p_A - p_B + r_t mod q
```

Final session key dan root berikutnya:

```text
SK_t      = HKDF(κ_t || K_raw || H(transcript), "session-key")
κ_(t+1)   = HKDF(κ_t || K_raw || H(transcript), "root-update")
```

Pada ONE_MIND:

```text
DIPP → menghasilkan K_wrap
AES-256-GCM → mengenkripsi K_file dan file
Server → menyimpan ciphertext saja
PKI → digunakan untuk enrollment dan trust establishment
```

Bagian yang masih memerlukan penelitian lanjutan adalah formal AKE security proof, fixed-point/constant-time implementation, endpoint-compromise analysis, post-compromise recovery, multi-session cryptanalysis, dan asynchronous prekey extension.

---

## 31. Referensi Konseptual

- Geometric median dan Weiszfeld method.
- Regev-style reconciliation dan bounded-error decoding.
- HMAC security model.
- HKDF extract-and-expand.
- AES-256-GCM authenticated encryption.
- Stateful symmetric ratchet dan transcript binding.

Referensi BibTeX jurnal dapat dimasukkan dari `sn-bibliography.bib` pada naskah DIPP.
