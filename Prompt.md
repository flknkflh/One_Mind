# ONE_MIND — Current Implementation Context

Dokumen ini adalah konteks teknis ringkas untuk pengembang/AI yang melanjutkan repository. Acuan utama tetap kode. Status dicocokkan pada 18 Juli 2026.

## Project Scope

ONE_MIND adalah prototipe encrypted web drive berbasis FastAPI, JavaScript browser, SQLite, Docker, dan Caddy. File dienkripsi di browser menggunakan AES-256-GCM. AES file key dibungkus per penerima menggunakan implementasi DIPP-KEM custom/prototipe.

Do not describe this project as production-ready, military-grade, formally zero-knowledge, or cryptographically audited.

## Current Architecture

### Frontend

- Static files: `static/index.html`, `static/app.js`, `static/styles.css`.
- No frontend framework or external CDN.
- Web Crypto API for RSA, AES-GCM, SHA-256, and randomness.
- DIPP implementation is embedded in `static/app.js`.
- Ciphertext is uploaded in chunks after encryption in browser memory.

### Backend

- FastAPI entry point: `app/main.py`.
- SQLite for users, administrators, certificates, audit events, files, shares, and upload sessions.
- JSON envelope files under the configured data directory.
- HMAC-signed custom bearer tokens.
- Trusted-host checking, CSP, security headers, and no-store responses.

### Deployment

- Local compose: Uvicorn HTTPS on port 8443 with local/self-signed certificate.
- Production compose: Uvicorn HTTP port 8080 inside Docker, Caddy terminates HTTPS on 443.

## Identity and Registration

Registration collects:

- username;
- display name;
- password;
- NIP;
- rank;
- position;
- DIPP public key;
- RSA login public key.

The browser generates DIPP and RSA keypairs. The server stores both public keys and a PBKDF2-SHA-256 password hash. A new account is `PENDING` until administrator approval.

The browser exports DIPP and RSA identity files. **Current exports contain unencrypted private-key material.** Do not claim that backup export uses PBKDF2 600,000 iterations or AES-GCM; that was an earlier design and is not the active implementation.

## Authentication

User authentication is two-stage:

1. `/api/login` verifies password and account status, returning a short-lived pending-login token.
2. `/api/login/challenge` returns a nonce.
3. Browser signs the nonce using the imported RSA Login private key.
4. `/api/login/verify` checks public-key equality, signature, account status, and certificate state.
5. The backend issues the main bearer token.

The first successful RSA verification automatically issues an internal user certificate if none exists. Later logins require the latest certificate to remain active and unexpired.

Admin authentication uses separate password login and admin bearer tokens.

Passwords are sent to the server over TLS. Authentication is not PAKE/OPAQUE/SRP.

## Browser Storage and RAM

`localStorage` keys:

- `om_token`
- `om_username`
- `om_admin_token`
- `om_admin_username`

DIPP and RSA private keys are not persisted in `localStorage` by current code. Imported/generated keys live in tab memory. DIPP identity, RSA CryptoKey, AES keys, raw AES key bytes during wrapping, plaintext, ciphertext, form passwords, pending tokens, and loaded API data may all exist temporarily in RAM.

The previously planned 15-minute private-key auto-lock is commented out and not active. Do not document it as implemented.

## File Workflow

### Upload

1. Generate AES-256-GCM key and IV.
2. Encrypt file in browser.
3. Calculate SHA-256 of ciphertext.
4. Wrap AES key for owner using DIPP public key.
5. Start upload session.
6. Send base64 ciphertext chunks.
7. Finish upload with envelope, hash, and owner wrapped key.
8. Backend merges chunks, validates hash, and stores envelope/share metadata.

### Download

1. Authenticated user requests a file for which a share record exists.
2. Server returns envelope and that user's wrapped key.
3. Browser unwraps AES key using DIPP private identity in RAM.
4. Browser decrypts and downloads plaintext.

### Share

Owner unwraps the current AES key locally and wraps it for the recipient's DIPP public key. Permission is `viewer` or `editor`.

### Update/Rotate

Owner or editor encrypts replacement content with a new AES key and submits a wrapped key for every currently authorized user. Backend requires the submitted recipient set to match current access.

### Revoke

Only owner may revoke. Revocation removes future server access but cannot erase plaintext/key/ciphertext already copied. Rotate for subsequent versions.

## Authorization Roles

- `owner`: read, rename, update/rotate, manage access, delete.
- `editor`: read, rename, update/rotate.
- `viewer`: read/decrypt.

## Administrator Capabilities

- Initialize first administrator.
- Login and change admin password.
- List users grouped by account/certificate status.
- Edit display name, NIP, rank, and position.
- Approve, reject, revoke, restore, and soft-delete accounts.
- Record administrative audit events.

## Security Facts That Must Remain Explicit

- DIPP-KEM is custom/prototype and not a substitute for an audited standard KEM.
- User/admin tokens in `localStorage` are accessible to same-origin JavaScript.
- A compromised/operator-controlled server can serve modified frontend JavaScript and steal browser secrets.
- Exported DIPP/RSA private keys are not encrypted by the current app.
- Private key auto-lock is inactive.
- Login rate limiting is in-process memory and resets on restart.
- Repository currently tracks CA/TLS private keys, server signing secret, databases, and runtime data; these must be removed from source control and rotated before real deployment.
- TLS protects data in transit but not against a malicious server endpoint.

## Compatibility Guidance

- Do not silently change or remove existing endpoints.
- Database migrations must preserve existing user/file/share/certificate data.
- Changes to DIPP/envelope/wrapped-key formats require explicit versioning and migration.
- Changes to key export must support a safe transition from existing plaintext export files.
- Documentation must describe implemented behavior and separately label planned behavior.

## Primary Documentation

- `README.md`: overview and quick start.
- `docs/MANUAL_BOOK.md`: operation, workflows, and endpoint inventory.
- `docs/SECURITY.md`: threat model, limitations, and hardening.
- `docs/TLS_MIGRATION.md`: local/intranet/production TLS deployment.
- `Referensi_Awal_Prototype.md`: status of historical prototype sources.
