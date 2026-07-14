# PROJECT CONTEXT

You are working on an existing project called ONE_MIND.

DO NOT rewrite the project from scratch.

DO NOT replace existing architecture.

FIRST understand the existing implementation before modifying anything.

This project already has a strong foundation and many security mechanisms have been implemented.

Your first responsibility is to preserve compatibility and stability.

Always read the related code before making changes.

Never remove existing functionality unless explicitly instructed.

Always implement new features incrementally.

========================================================
PROJECT OVERVIEW
========================================================

ONE_MIND is a secure document management and encrypted file sharing platform.

The goal is not merely encrypted storage.

The goal is to build a complete secure document ecosystem with:

- Identity Management
- Public Key Infrastructure (PKI)
- Digital Certificates
- Secure File Encryption
- Secure Sharing
- Accountability
- Audit Trail
- Certificate Lifecycle
- Zero Knowledge Server for Private Keys

The project is intended for defense / military / government style environments where accountability and cryptographic identity are mandatory.

========================================================
CURRENT FOUNDATION (ALREADY IMPLEMENTED)
========================================================

The following components already exist and MUST be preserved.

### Authentication

- Username / Password
- JWT authentication

### DIPP Identity

The browser generates a DIPP keypair.

The DIPP private key NEVER leaves the client.

The server stores ONLY the DIPP public key.

Identity can be exported/imported.

### File Encryption

Hybrid Encryption

AES-GCM

Wrapped file keys

Chunked upload

Resume upload

Upload session management

Automatic cleanup

### PKI Foundation

RSA keypair generation inside browser

PKI private key NEVER leaves browser

PKI public key stored on server

Challenge endpoint

Proof of Possession implemented

RSA Signature verification already implemented

Certificate Request database already exists

Certificate table already exists

Certificate Revocation table already exists

========================================================
CURRENT ARCHITECTURE
========================================================

Client

↓

Generate DIPP

↓

Generate PKI RSA

↓

Register

↓

Server stores

- DIPP Public Key

- PKI Public Key

↓

Private Keys remain inside browser

========================================================
CURRENT DEVELOPMENT DIRECTION
========================================================

We are now expanding the identity lifecycle.

The architecture MUST evolve carefully without breaking previous functionality.

========================================================
TARGET ARCHITECTURE
========================================================

Identity lifecycle:

Register

↓

Generate Identity

↓

Administrator Approval

↓

Certificate Request

↓

Proof of Possession

↓

Certificate Issue

↓

Certificate Usage

↓

Certificate Renewal

↓

Certificate Revocation

↓

Certificate Replacement

========================================================
NEW IDENTITY MODEL
========================================================

User registration now includes:

- Username

- Display Name

- Password

- NIP

- Rank

- Position

The users table should evolve to include:

username

display_name

password_hash

nip

rank

position

public_key

pki_public_key

account_status

certificate_status

created_at

approved_at

approved_by

revoked_at

revoked_by

deleted_at

deleted_by

========================================================
ACCOUNT STATUS
========================================================

PENDING

ACTIVE

REJECTED

DELETED

========================================================
CERTIFICATE STATUS
========================================================

NONE

ISSUED

REVOKED

EXPIRED

REPLACED

Account Status and Certificate Status MUST remain independent.

========================================================
ADMINISTRATOR
========================================================

An administrator portal will be added.

Administrator authentication is completely separate from user authentication.

Initially administrator only uses:

Username

Password

Future capabilities:

Approve User

Reject User

Edit User Metadata

Revoke User

Restore User

Delete User (soft delete)

Issue Certificate

Revoke Certificate

View Audit Logs

========================================================
IDENTITY FILE
========================================================

The project is moving away from DIPP-only identity.

Eventually a unified ONE_MIND Identity file will exist.

It will contain:

DIPP Keys

PKI Keys

Certificate

Metadata

Version

The server NEVER stores private keys.

========================================================
IMPORTANT DESIGN RULES
========================================================

Never store any private key on the server.

Never transmit private keys over the network.

Only public keys are stored server-side.

Proof of Possession must always verify ownership of the private key.

Backward compatibility is important.

Prefer database migrations over destructive schema changes.

Do not remove existing endpoints unless instructed.

========================================================
WORKFLOW
========================================================

Before implementing anything:

1. Read existing implementation.

2. Explain the impact.

3. Implement minimal safe changes.

4. Verify existing features still work.

5. Suggest testing procedure.

========================================================
GIT RULES
========================================================

Every completed feature MUST end with:

git status

git add .

git commit -m "<clear commit message>"

Keep commits focused.

========================================================
FINAL GOAL
========================================================

Build ONE_MIND into a secure enterprise-grade document management system with:

- Identity Management

- PKI

- Certificate Lifecycle

- Secure File Encryption

- Secure Sharing

- Accountability

- Cryptographic Audit Trail

without breaking the already existing secure foundation.