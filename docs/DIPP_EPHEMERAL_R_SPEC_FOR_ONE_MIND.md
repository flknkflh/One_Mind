# DIPP Ephemeral-R Integration Specification for ONE_MIND

**Status:** research implementation specification  
**Revision:** weighted standalone pre-key + HKDF wrapping E2048 R10S12S Q2500K v5

**Integration decision date:** 2026-07-27

This is the active ONE_MIND integration contract. The 25 July research paper
describes direct wrapping of the 256 AES-key bits. By explicit integration
decision, ONE_MIND instead encapsulates an independent 256-bit pre-key, derives
`K_DIPP` with transcript-bound HKDF, and uses `K_DIPP` to wrap the AES file key.

There is no ECDH and no hybrid combiner.

## Security status

DIPP remains a research functional-LWE candidate. Correctness experiments do
not establish hardness. This profile is not a standardized KEM, is not proven
IND-CCA secure, and must not be represented as production post-quantum
cryptography.

The weighted profile intentionally broadens the marginal distribution of
`k_Ai`. Local exploratory sweeps still recovered substantially more than random
chance with a public `U_i`/`B_B` proxy. Weighting therefore does not establish
confidentiality; it only weakens the original trivial fixed-threshold
separation.

## Recipient key model

```text
SK_B = x_B
PK_B = (seed_A, B_B, params, key_id)
B_B  = GM(A union {x_B}) + eta_B
```

Only the recipient has a static DIPP secret point. Alice generates a fresh
secret `R_i` for each pre-key bit. The wire field `B_b` is the canonical
serialized name for paper notation `B_B`.

## Parameter profile `ER-DIPP-64-16-W8-E2048-R10S12S-Q2500K-v5`

| Parameter | Value |
|---|---:|
| Dimension `d` | 64 |
| Public points `n` | 16 |
| Coordinate/fixed-point scale | 1,000,000 |
| Secret-point weight | 8 |
| Secret radius | Uniform integer permille in `[10 S_pub,12 S_pub]` |
| Geometric noise radius | `0` in weighted E2048 R10S12S Q2500K v5 correctness profile |
| Modulus `q` | 65,536 |
| Quantization scale | 2,500,000 |
| Integer noise distribution | Uniform discrete `[-2048,2048]` |
| Decoder radius | 16,384 |
| Pre-key | 256 bits |
| Fixed Weiszfeld iterations | 24 |

## Public geometry and recipient generation

```text
A     = DerivePoints(seed_A, d, n, coordinate_range)
G     = GM(A)
S_pub = sqrt((1/n) sum ||a_i-G||^2)
F(c;A)= (1/(n S_pub)) sum ||c-a_i||

x_B   = G + rho_B S_pub u_B, rho_B <- Uniform[10,12]
P_B   = GM(A union {x_B repeated 8 times})
B_B   = P_B + eta_B
```

The implementation uses SHAKE-256 rejection sampling, signed big-endian
vectors, fixed-point integer arithmetic, signed nearest rounding, canonical
modular reduction, explicit singular handling, and 24 Weiszfeld iterations.
The private point exists only in the encrypted `.dipp` vault.

## Alice encapsulates a pre-key

Alice samples:

```text
preKey <- CSPRNG(256 bits)
preKey = z_1 || ... || z_256
```

For every `z_i`:

```text
rho_i <- Uniform integer permille in [10,12]
R_i   = G + rho_i S_pub u_i
P_i   = GM(A union {R_i repeated 8 times})
U_i   = P_i + eta_i
C_Ai  = GM(A union {R_i repeated 8 times,B_B repeated 8 times})
k_Ai  = round(2,500,000 * F(C_Ai;A)) mod 65,536
e_i   <- UniformDiscrete[-2048,2048]
V_i   = k_Ai + z_i * 32,768 + e_i mod 65,536
```

The DIPP encapsulation is exactly 256 pairs:

```text
ct_DIPP = {(U_i,V_i)} for i=1..256
```

`R_i` and intermediate geometric state are cleared after every component.

## Bob reconstructs the pre-key

```text
C_Bi     = GM(A union {x_B repeated 8 times,U_i repeated 8 times})
k_Bi     = round(2,500,000 * F(C_Bi;A)) mod 65,536
residual = V_i-k_Bi mod 65,536
z_i      = nearest modular center in {0,32,768}
preKey   = z_1 || ... || z_256
```

Correctness requires the total reconciliation error to remain below `q/4`.

## Empirical reconciliation audit

The `e_i` range was increased gradually on one fixed geometry corpus so every
candidate was compared against the same 8 identities, 32 pre-keys, and 8,192
decoded bits. The geometry-only maximum reconciliation error was 12,827 and
the decoder limit was 16,384.

| Integer-noise range | Correct bits | Correct pre-keys | Maximum total error | Observed margin |
|---|---:|---:|---:|---:|
| `[-64,64]` | 8,192/8,192 | 32/32 | 12,828 | 3,556 |
| `[-1024,1024]` | 8,192/8,192 | 32/32 | 13,290 | 3,094 |
| `[-2048,2048]` | 8,192/8,192 | 32/32 | 13,548 | 2,836 |
| `[-3072,3072]` | 8,192/8,192 | 32/32 | 15,346 | 1,038 |
| `[-4096,4096]` | 8,191/8,192 | 31/32 | 16,506 | -122 |

`[-2048,2048]` is therefore the selected experimental bound. The corpus also
gives a conservative geometry-plus-bound margin of
`16,384 - 12,827 - 2,048 = 1,509`. The sample does not prove correctness for
all keys or establish a formal failure probability.

Increasing this reconciliation noise did not materially remove visible
statistical structure: on the same corpus, a raw `V_i` threshold classified
about 71.92% at bound 64 and 71.80% at bound 2,048. This parameter change is a
correctness-constrained experiment, not a confidentiality proof.

## Transcript-bound key derivation

The canonical transcript binds:

- version and parameter profile;
- sender and recipient IDs;
- recipient key ID, public seed, and `B_B`;
- all 256 `(U_i,V_i)` pairs;
- unique session ID and file-context ID;
- geometry, extractor, and key-establishment identifiers.

Both endpoints compute:

```text
transcript_hash = SHA-256(canonical_transcript)

K_DIPP = HKDF-SHA-256(
    IKM  = preKey,
    salt = transcript_hash,
    info = "ONE_MIND-DIPP-EPHEMERAL-R-WEIGHTED-E2048-R10S12S-Q2500K-v5",
    L    = 32 bytes
)
```

The sender signs `transcript_hash` with its RSA-4096 authentication key.

## AES file-key wrapping

The independently generated AES file key is wrapped with AES-256-GCM:

```text
wrapped_file_key = AES-256-GCM-Encrypt(
    key       = K_DIPP,
    nonce     = wrap_nonce,
    plaintext = K_AES,
    AAD       = canonical(
        version,
        session_id,
        file_context_id,
        sender_id,
        recipient_id,
        transcript_hash
    )
)
```

The wrapped-key envelope contains:

```text
ct_DIPP
transcript_hash
wrap_nonce
wrapped_file_key
sender_signature
```

File contents are separately encrypted with `K_AES` using AES-256-GCM.

## Mandatory validation

Reject input when:

- version/profile/user/key/public-material binding differs;
- the component count is not exactly 256;
- a vector is non-canonical, has the wrong dimension, or leaves the accepted
  coordinate domain;
- `V_i` is outside `Z_q`;
- a component, session, or transcript is reused;
- transcript hash or RSA signature validation fails;
- `wrap_nonce` is not 12 bytes or wrapped ciphertext is not 48 bytes;
- file-context binding or AEAD authentication fails.

The active envelope version is:

```text
ONE_MIND-DIPP-EPHEMERAL-R-WEIGHTED-E2048-R10S12S-Q2500K-v5
```

Decapsulation exposes only a generic failure and does not reveal which bit,
component, transcript check, or AEAD check failed.
