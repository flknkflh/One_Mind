# ONE_MIND DIPP — Current Implemented Specification v5

**Status:** implemented and active
**Date:** 17 August 2026
**Scope:** browser cryptography, DIPP key establishment, file-key wrapping,
server validation, and Docker deployment
**Security status:** experimental research profile; not a standardized or
formally proven KEM

This document is the authoritative technical snapshot of the DIPP profile that
is currently implemented by ONE_MIND DIPP. Historical DIPP documents may
describe older radii, quantization scales, envelope versions, or noise bounds.

## 1. Active identifiers

| Identifier | Current value |
|---|---|
| Protocol | `ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE` |
| Protocol version | `5` |
| Parameter set | `ER-DIPP-64-16-W8-E2048-R10S12S-Q2500K-v5` |
| Envelope version | `ONE_MIND-DIPP-EPHEMERAL-R-WEIGHTED-E2048-R10S12S-Q2500K-v5` |
| File protocol | `ONE_MIND_DIPP_EPHEMERAL_R_WEIGHTED_E2048_R10S12S_Q2500K_V5` |
| Geometry profile | `FIXED-WEISZFELD-24-WEIGHTED-8-R10S12S` |
| Key establishment | `DIPP-ER-WEIGHTED-E2048-R10S12S-Q2500K-v5` |
| Vault type | `ONE_MIND_DIPP_EPHEMERAL_R_IDENTITY` |
| Vault version | `11` |
| Key-ID domain | `DIPP-ER-WEIGHTED-E2048-R10S12S-Q2500K-KEY-ID-v5` |

Version identifiers are cryptographic domain separators and compatibility
barriers. A v5 client rejects identities, vaults, and envelopes from older
profiles instead of silently processing them with different parameters.

## 2. Parameter table

| Parameter | Symbol | Value |
|---|---:|---:|
| Dimension | `d` | 64 |
| Number of public points | `n` | 16 |
| Public coordinate domain |  | `[-1,000,000, 1,000,000]` |
| Fixed-point coordinate scale |  | 1,000,000 |
| Secret-point weight | `W` | 8 |
| Minimum secret radius |  | `10 S_pub` |
| Maximum secret radius |  | `12 S_pub` |
| Radius sampling |  | uniform integer permille `[10000,12000]` |
| Geometric vector noise | `eta` | 0 |
| Modulus | `q` | 65,536 |
| Half-modulus encoding | `q/2` | 32,768 |
| Decoder radius | `q/4` | 16,384 |
| Quantization scale | `Q_quant` | 2,500,000 |
| Scalar reconciliation error | `e_i` | uniform discrete `[-2048,2048]` |
| Secret point coordinate weight |  | 8 repeated references |
| Pre-key size |  | 256 bits / 32 bytes |
| DIPP components |  | 256 |
| Fixed Weiszfeld iterations |  | 24 |
| Maximum absolute coordinate |  | 34,000,000 |
| Internal Weiszfeld weight scale |  | `2^52` |

`S_pub` is computed independently for each recipient public identity.

## 3. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Browser randomness | Web Crypto `getRandomValues` |
| Public-point derivation | SHAKE-256 with rejection sampling |
| Transcript hashing | SHA-256 |
| DIPP extraction | HKDF-SHA-256 |
| File encryption | AES-256-GCM |
| File-key wrapping | AES-256-GCM |
| Local DIPP vault | PBKDF2-SHA-256 + AES-256-GCM |
| Sender authentication | RSA-4096, RSASSA-PKCS1-v1_5, SHA-512 |
| Ciphertext integrity checksum | SHA-256 in the file envelope |

RSA authentication is classically strong at the configured size but is not a
post-quantum signature scheme.

## 4. Integer and wire representation

- Geometry is evaluated with JavaScript `BigInt` intermediates.
- Signed division uses nearest-integer rounding.
- Every point has exactly 64 signed coordinates.
- A point is serialized as 64 signed int32 values in big-endian order, for a
  total of 256 bytes before Base64URL encoding.
- Binary fields use canonical unpadded Base64URL.
- Scalar `V_i` is an integer in `[0,65535]`.
- Bits are extracted from the 32-byte pre-key in most-significant-bit-first
  order.
- JSON transcript objects are recursively canonicalized by sorted object keys
  before hashing.

Non-canonical encodings, unexpected fields, invalid lengths, out-of-domain
coordinates, and duplicate DIPP components are rejected.

## 5. Public geometry

For recipient public seed `seed_B`, derive:

```text
A = DerivePoints(
      domain = "DIPP-ER-PUBLIC-POINTS-v1",
      seed   = seed_B,
      count  = 16,
      d      = 64
    )
```

The public cloud is:

```text
A = {A_1,...,A_16}, A_j in Z^64
```

Its geometric median is:

```text
G = GM(A)
```

The public scale is the integer root-mean-square radius:

```text
S_pub = sqrt(round((1/16) sum_j ||A_j-G||^2))
```

The normalized public functional is:

```text
F(C;A) = (sum_j ||C-A_j||) / (16 S_pub)
```

The implementation does not evaluate this as floating point. It keeps the
distance sum and denominator as integers, then performs signed nearest rounding
during quantization.

## 6. Weighted geometric median

Weight eight is implemented by inserting the same point eight times. Thus:

```text
GM(A union [X]^8)
```

minimizes the objective:

```text
sum_j ||Z-A_j|| + 8 ||Z-X||
```

For two weighted points:

```text
GM(A union [X]^8 union [Y]^8)
```

minimizes:

```text
sum_j ||Z-A_j|| + 8 ||Z-X|| + 8 ||Z-Y||
```

The same secret point is repeated; `W=8` does not mean eight independent
secrets and does not add eight times the entropy.

The geometric median uses a fixed 24-iteration integer Weiszfeld solver. A
singular point is handled explicitly if the current center equals an input
point.

## 7. Recipient identity generation

Bob generates:

```text
publicSeed <- CSPRNG(32 bytes)
A          = DerivePoints(publicSeed)
G          = GM(A)
S_pub      = PublicScale(A,G)
rho_B      <- UniformInteger{10000,...,12000}
d_B        <- RandomDirection(64)
r_B        = floor(S_pub rho_B / 1000)
x_B        = G + r_B normalize(d_B)
```

Therefore:

```text
10 S_pub <= ||x_B-G|| <= 12 S_pub
```

The public weighted summary is:

```text
P_B = GM(A union [x_B]^8)
B_b = P_B
```

Geometric vector noise is disabled, so `B_b` is the fixed-point result itself.

Bob publishes:

```text
protocol, version, type, user_id, key_id,
parameter_profile, public_seed, B_b
```

Bob keeps only `x_B` private. The key ID is:

```text
key_id = SHA-256(
  key-id-domain || username || publicSeed || EncodeInt32BE(B_b)
)
```

## 8. Local DIPP identity vault

The private state is exactly:

```json
{"bob_private_point":"<base64url int32 vector>"}
```

Vault-key derivation:

```text
salt       <- CSPRNG(16 bytes)
vaultKey   = PBKDF2-SHA-256(password, salt, 600000 iterations, 256 bits)
nonce      <- CSPRNG(12 bytes)
```

The private state is encrypted with AES-256-GCM. The canonical vault header,
including the public key and KDF parameters, is supplied as AES-GCM additional
authenticated data. Vault parameters and object fields must match the v11
schema exactly.

## 9. File encryption

For a new file version, the browser creates:

```text
K_file <- CSPRNG(32 bytes)
N_file <- CSPRNG(12 bytes)
```

File plaintext is encrypted in the browser:

```text
C_file = AES-256-GCM(K_file, N_file, AAD_file, plaintext)
```

The server stores encrypted file bytes and the validated file envelope. The
file key is never intentionally sent to the server in plaintext.

Large ciphertext is transferred and stored as bounded chunks. The complete
ciphertext SHA-256, byte length, chunk index, and total chunk count are checked
during download before AES-GCM decryption.

## 10. Alice DIPP encapsulation

Alice validates the recipient public identity and reconstructs `A`, `G`, and
`S_pub` from the recipient seed.

Alice samples one independent pre-key per wrapped file key:

```text
preKey <- CSPRNG(32 bytes)
preKey = z_1 || ... || z_256
```

For every bit `z_i`, Alice samples a fresh ephemeral point:

```text
rho_i <- UniformInteger{10000,...,12000}
d_i   <- RandomDirection(64)
r_i   = floor(S_pub rho_i / 1000)
R_i   = G + r_i normalize(d_i)
```

Alice produces the transmitted vector:

```text
P_i = GM(A union [R_i]^8)
U_i = P_i
```

Alice's cross-point and quantized functional are:

```text
C_Ai = GM(A union [R_i]^8 union [B_b]^8)

k_Ai = round(
          2500000 *
          (sum_j ||C_Ai-A_j||) /
          (16 S_pub)
        ) mod 65536
```

Alice samples scalar error:

```text
e_i <- UniformDiscrete[-2048,2048]
```

and encodes the bit:

```text
V_i = k_Ai + z_i * 32768 + e_i mod 65536
```

One encapsulation contains exactly:

```text
ct_DIPP = {(U_i,V_i)} for i=1..256
```

`R_i` and intermediate arrays are cleared on a best-effort basis after each
component. JavaScript zeroization is not a formal guarantee against browser or
process memory compromise.

## 11. Transcript construction

The canonical transcript contains:

```text
version
parameter_profile
sender_id
recipient_id
recipient_key_id
public_seed
B_b
session_id
file_context_id
dipp_components[256]
algorithms.geometry
algorithms.extractor
algorithms.key_establishment
```

`session_id` and `file_context_id` are each exactly 24 random bytes before
Base64URL encoding.

The transcript hash is:

```text
T = SHA-256(CanonicalJSON(transcript))
```

## 12. DIPP key extraction

Alice computes:

```text
K_DIPP = HKDF-SHA-256(
  IKM  = preKey,
  salt = T,
  info = UTF8(envelopeVersion),
  L    = 32 bytes
)
```

The transcript hash is a public salt and context binding, not an additional
secret. HKDF cannot create entropy that is absent from the pre-key.

## 13. File-key wrapping and sender authentication

Alice samples a 12-byte wrap nonce and encrypts the raw 32-byte file key:

```text
wrapped_file_key = AES-256-GCM(
  key       = K_DIPP,
  nonce     = wrap_nonce,
  aad       = CanonicalJSON({
                version,
                session_id,
                file_context_id,
                sender_id,
                recipient_id,
                transcript_hash
              }),
  plaintext = K_file
)
```

The wrapped value is exactly 48 bytes: 32 plaintext bytes plus a 16-byte GCM
tag.

Alice signs `T` with RSA-4096, RSASSA-PKCS1-v1_5, and SHA-512. The resulting
signature is exactly 512 bytes. The receiver obtains the sender public signing
key through the application's PKI endpoint and verifies the signature before
accepting the wrapped key.

## 14. Bob decapsulation

Bob verifies the envelope schema, profile identifiers, recipient binding,
transcript hash, and sender signature. Bob loads `x_B` from the unlocked vault.

For each component:

```text
C_Bi = GM(A union [x_B]^8 union [U_i]^8)

k_Bi = round(
          2500000 *
          (sum_j ||C_Bi-A_j||) /
          (16 S_pub)
        ) mod 65536

residual_i = V_i-k_Bi mod 65536
d0         = circularDistance(residual_i,0)
d1         = circularDistance(residual_i,32768)
z_i        = 1 if d1 < d0 else 0
```

Bob reconstructs:

```text
preKey_B = z_1 || ... || z_256
```

and derives `K_DIPP` with the same transcript hash and version info. Bob then
opens `wrapped_file_key`. AES-GCM authentication failure rejects the entire
operation. A one-bit pre-key error is sufficient to produce an unrelated
`K_DIPP` and fail the GCM tag.

## 15. Correctness condition

Define the circular reconciliation error:

```text
E_i = dist_q(k_Ai + e_i, k_Bi)
```

Correct decoding requires:

```text
E_i < q/4 = 16384
```

Observed margin is:

```text
margin = 16384 - max_i(E_i)
```

Current 16,384-bit validation result:

| Metric | Result |
|---|---:|
| Correct bits | 16,384 / 16,384 |
| Correct 256-bit pre-keys | 64 / 64 |
| Maximum observed error | 8,276 |
| Observed margin | 8,108 |

This is an empirical result, not a formal upper bound over every possible
public cloud, secret direction, radius, and scalar error.

## 16. Current V-only classifier audit

On the same 16,384-bit validation corpus:

| Classifier | Test accuracy |
|---|---:|
| Fixed threshold at `q/2` | 50.23% |
| Trained circular threshold | approximately 50% |
| 32-bin histogram classifier | 50.99% |

These results show that the tested one-dimensional classifiers cannot
distinguish the pre-key bit better than sampling noise. They do not prove that
`V_i`, `(U_i,V_i)`, or the full transcript is pseudorandom.

## 17. Replay and server validation

The server validates both public identities and wrapped-key envelopes before
storage. Important rules include:

- exact object schemas with no unknown fields;
- exact protocol and parameter identifiers;
- exactly 256 DIPP components;
- canonical 256-byte `U_i` vectors;
- `0 <= V_i < 65536`;
- no duplicate `(U_i,V_i)` component;
- 32-byte public seed and transcript hash;
- 24-byte session and file-context identifiers;
- 12-byte wrap nonce;
- 48-byte wrapped file key;
- 512-byte RSA signature;
- canonical sender and recipient identifiers;
- server-side verification of the sender transcript signature.

Replay protection is backed by a primary key on `session_id` and a unique
constraint on `transcript_hash` in `dipp_ciphertexts`.

The server intentionally stores public identity material, public transcript,
wrapped key, encrypted file bytes, and application metadata. It should not know
`x_B`, `R_i`, the pre-key, `K_DIPP`, `K_file`, or plaintext during an honest
client execution.

## 18. Web and session security

Current server controls include:

- strict Pydantic input models;
- bounded usernames, opaque identifiers, filenames, file sizes, chunks, and
  request bodies;
- parameterized SQLite operations;
- rejection of API query parameters where they are not supported;
- `application/json` enforcement for state-changing API requests;
- mandatory and bounded `Content-Length`;
- Trusted Host middleware;
- CSP, `X-Content-Type-Options`, `X-Frame-Options`, no-referrer policy, and
  restricted Permissions Policy;
- HSTS on HTTPS responses;
- `Cache-Control: no-store` for the root and API responses;
- five-minute default user and administrator idle/expiry windows.

Browser login tokens are currently stored in `localStorage`. An XSS, malicious
extension, compromised browser, or compromised JavaScript delivery path can
therefore steal tokens and potentially unlocked cryptographic state.

## 19. Docker deployment

| Setting | Active value |
|---|---|
| Compose project | `one-mind-dipp` |
| Container | `one_mind_dipp` |
| Host port | `8444` |
| Container HTTPS port | `8443` |
| TLS mode | `internal` |
| Data volume | `./data:/app/data` |
| Certificate volume | `./certs:/app/certs` |
| Restart policy | `unless-stopped` |

The container health endpoint currently reports:

```json
{
  "ok": true,
  "transport": "HTTPS/TLS when run via docker entrypoint",
  "crypto_profile": "ONE_MIND_DIPP_EPHEMERAL_R_WEIGHTED_E2048_R10S12S_Q2500K_V5",
  "server_knowledge": "public-transcript-and-ciphertext-only"
}
```

The service is exposed locally at `https://localhost:8444`. Access from another
device uses the current server LAN address and requires firewall access plus a
certificate chain trusted by that device.

## 20. Measured local performance

Three post-warm-up runs were averaged for each file size. Persistence used a
real temporary disk write/read; network and Wi-Fi latency were excluded.

| Size | AES encrypt | DIPP wrap | Disk write | Disk read | DIPP unwrap | AES decrypt | Total |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 MiB | 0.91 ms | 1,101.38 ms | 1.31 ms | 1.13 ms | 632.49 ms | 0.81 ms | 1,738.03 ms |
| 10 MiB | 6.59 ms | 1,109.08 ms | 3.89 ms | 4.60 ms | 632.92 ms | 6.29 ms | 1,763.36 ms |
| 50 MiB | 32.25 ms | 1,112.76 ms | 17.58 ms | 21.00 ms | 637.39 ms | 30.07 ms | 1,851.05 ms |

DIPP overhead is nearly constant because it always protects one 32-byte file
key with 256 components. AES and storage time grow with the file size.

## 21. Remaining attack surface

The following risks remain open and are not resolved by the near-50% V-only
classifier result:

1. **Inverse weighted-geometric-median attack.** `B_b` and every `U_i` are
   deterministic unnoised functions of secret points. The first-order geometric
   median equation may reveal a secret-point direction and reduce radius search
   to a much smaller problem.
2. **Joint `(U_i,V_i)` learning.** Existing threshold audits use `V_i`. A model
   consuming 64 coordinates of `U_i`, `V_i`, `B_b`, and public cloud features
   may extract signal not visible in a scalar histogram.
3. **Multi-ciphertext recipient attack.** Bob's `x_B` and `B_b` are reused,
   allowing an attacker to accumulate many transcripts for the same identity.
4. **No formal hardness reduction.** This construction is not reduced to LWE,
   SIS, a standard lattice problem, or another established assumption.
5. **No formal IND-CPA/IND-CCA proof.** Signature and AEAD provide important
   integrity layers but are not a proof for the complete construction.
6. **Empirical correctness only.** Rare geometries beyond the sampled corpus can
   still cause a bit error and make a file key unavailable.
7. **Password and endpoint compromise.** A stolen encrypted vault permits
   offline password guessing; an unlocked browser or malicious delivered script
   can read secrets directly.
8. **Non-post-quantum authentication.** RSA-4096 sender authentication is not
   resistant to a sufficiently capable quantum computer.
9. **Traffic metadata.** TLS hides contents but exposes endpoints, timing,
   packet sizes, transfer volume, and connection patterns.
10. **Client CPU denial of service.** Decapsulation performs 256 fixed-point
    geometric-median calculations and can be abused to consume browser CPU.

The current profile must therefore be described as a functioning experimental
key-establishment construction, not as a production-certified post-quantum KEM.

## 22. Verification commands

From the DIPP repository root:

```powershell
node tests/test_dipp_ephemeral_r.js
node tests/benchmark_dipp_file_flow.js
docker compose config --quiet
docker compose up -d --build
docker compose ps
docker compose exec -T one-mind curl --insecure --fail `
  https://127.0.0.1:8443/health
```

Research audit reports associated with this profile:

- `docs/DIPP_V5_PERFORMANCE_REPORT.md`
- workspace audit `SECRET_RADIUS_SWEEP_REPORT.md`
- workspace audit `QUANTIZATION_SCALE_SWEEP_REPORT.md`

## 23. Compatibility rule

Version 5 changes both secret-radius distribution and quantization scale. It is
not wire-compatible with v4. A v5 deployment requires v5 public identities and
v11 local vaults. Older encrypted vaults and wrapped keys are rejected by
design. At the time of migration, the application database contained no users,
files, or DIPP ciphertexts, so no stored user data required migration.
