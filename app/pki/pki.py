import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ============================================================
# PKI Folder
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("ONE_MIND_DATA_DIR", PROJECT_DIR / "data"))
BASE_DIR = Path(os.environ.get("ONE_MIND_PKI_DIR", DATA_DIR / "pki"))

ROOT_DIR = BASE_DIR / "root"
INTERMEDIATE_DIR = BASE_DIR / "intermediate"
ISSUED_DIR = BASE_DIR / "issued"
CSR_DIR = BASE_DIR / "csr"
REVOKED_DIR = BASE_DIR / "revoked"

for d in (
    ROOT_DIR,
    INTERMEDIATE_DIR,
    ISSUED_DIR,
    CSR_DIR,
    REVOKED_DIR,
):
    d.mkdir(
        parents=True,
        exist_ok=True
    )

ROOT_KEY = ROOT_DIR / "root_ca.key"
ROOT_CERT = ROOT_DIR / "root_ca.crt"

INTERMEDIATE_KEY = INTERMEDIATE_DIR / "intermediate_ca.key"
INTERMEDIATE_CERT = INTERMEDIATE_DIR / "intermediate_ca.crt"

# ============================================================
# Helper
# ============================================================

def save_private_key(path: Path, private_key):

    pem = private_key.private_bytes(

        encoding=serialization.Encoding.PEM,

        format=serialization.PrivateFormat.PKCS8,

        encryption_algorithm=serialization.NoEncryption(),

    )

    path.write_bytes(pem)
    path.chmod(0o600)


def save_certificate(path: Path, certificate):

    path.write_bytes(

        certificate.public_bytes(

            serialization.Encoding.PEM

        )

    )


def load_private_key(path: Path):

    return serialization.load_pem_private_key(

        path.read_bytes(),

        password=None,

    )


def load_certificate(path: Path):

    return x509.load_pem_x509_certificate(

        path.read_bytes()

    )

def load_public_key_from_cert(path: Path):

    cert = load_certificate(path)

    return cert.public_key()

# ============================================================
# Root CA
# ============================================================

def generate_root_ca():

    if ROOT_KEY.exists() and ROOT_CERT.exists():

        print("Root CA sudah ada.")

        return

    if ROOT_KEY.exists() or ROOT_CERT.exists():
        raise RuntimeError(
            "Material Root CA tidak lengkap. Pulihkan pasangan key/certificate dari backup atau lakukan rotasi terkontrol."
        )

    print("Membuat Root CA...")

    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=4096,

    )

    subject = issuer = x509.Name([

        x509.NameAttribute(

            NameOID.COUNTRY_NAME,

            "ID"

        ),

        x509.NameAttribute(

            NameOID.ORGANIZATION_NAME,

            "ONE_MIND"

        ),

        x509.NameAttribute(

            NameOID.COMMON_NAME,

            "ONE_MIND Root CA"

        ),

    ])

    certificate = (

        x509.CertificateBuilder()

        .subject_name(subject)

        .issuer_name(issuer)

        .public_key(private_key.public_key())

        .serial_number(

            x509.random_serial_number()

        )

        .not_valid_before(

            datetime.now(timezone.utc)

        )

        .not_valid_after(

            datetime.now(timezone.utc)

            + timedelta(days=3650)

        )

        .add_extension(

            x509.BasicConstraints(

                ca=True,

                path_length=1

            ),

            critical=True,

        )

        .add_extension(

            x509.KeyUsage(

                digital_signature=False,

                key_encipherment=False,

                content_commitment=False,

                data_encipherment=False,

                key_agreement=False,

                key_cert_sign=True,

                crl_sign=True,

                encipher_only=False,

                decipher_only=False,

            ),

            critical=True,

        )

        .sign(

            private_key,

            hashes.SHA512()

        )

    )

    save_private_key(

        ROOT_KEY,

        private_key

    )

    save_certificate(

        ROOT_CERT,

        certificate

    )

    print("Root CA berhasil dibuat.")

    # ============================================================
# Intermediate CA
# ============================================================

def generate_intermediate_ca():

    if INTERMEDIATE_KEY.exists() and INTERMEDIATE_CERT.exists():

        print("Intermediate CA sudah ada.")

        return

    if INTERMEDIATE_KEY.exists() or INTERMEDIATE_CERT.exists():
        raise RuntimeError(
            "Material Intermediate CA tidak lengkap. Pulihkan pasangan key/certificate dari backup atau lakukan rotasi terkontrol."
        )

    if not ROOT_KEY.exists() or not ROOT_CERT.exists():

        raise RuntimeError(
            "Root CA belum dibuat."
        )

    print("Membuat Intermediate CA...")

    root_key = load_private_key(
        ROOT_KEY
    )

    root_cert = load_certificate(
        ROOT_CERT
    )

    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=4096,

    )

    subject = x509.Name([

        x509.NameAttribute(
            NameOID.COUNTRY_NAME,
            "ID"
        ),

        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "ONE_MIND"
        ),

        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "ONE_MIND Intermediate CA"
        ),

    ])

    certificate = (

        x509.CertificateBuilder()

        .subject_name(subject)

        .issuer_name(
            root_cert.subject
        )

        .public_key(
            private_key.public_key()
        )

        .serial_number(
            x509.random_serial_number()
        )

        .not_valid_before(
            datetime.now(timezone.utc)
        )

        .not_valid_after(
            datetime.now(timezone.utc)
            + timedelta(days=1825)
        )

        .add_extension(

            x509.BasicConstraints(

                ca=True,

                path_length=0

            ),

            critical=True,

        )

        .add_extension(

            x509.KeyUsage(

                digital_signature=False,

                key_encipherment=False,

                content_commitment=False,

                data_encipherment=False,

                key_agreement=False,

                key_cert_sign=True,

                crl_sign=True,

                encipher_only=False,

                decipher_only=False,

            ),

            critical=True,

        )

        .sign(

            root_key,

            hashes.SHA512()

        )

    )

    save_private_key(
        INTERMEDIATE_KEY,
        private_key
    )

    save_certificate(
        INTERMEDIATE_CERT,
        certificate
    )

    print("Intermediate CA berhasil dibuat.")


def initialize_pki(auto_init: bool = True):
    """Pastikan material CA tersedia di storage runtime, bukan di source tree."""

    required = (
        ROOT_KEY,
        ROOT_CERT,
        INTERMEDIATE_KEY,
        INTERMEDIATE_CERT,
    )

    if all(path.exists() for path in required):
        return

    if not auto_init:
        missing = ", ".join(str(path) for path in required if not path.exists())
        raise RuntimeError(
            "PKI belum diprovisikan untuk deployment ini. File yang belum tersedia: "
            f"{missing}"
        )

    generate_root_ca()
    generate_intermediate_ca()


def intermediate_ca_fingerprint() -> str:
    certificate = load_certificate(INTERMEDIATE_CERT)
    return certificate.fingerprint(hashes.SHA256()).hex()


def certificate_matches_current_intermediate(certificate_pem: str) -> bool:
    """Validasi issuer dan signature certificate terhadap Intermediate CA aktif."""

    try:
        certificate = x509.load_pem_x509_certificate(
            certificate_pem.encode("utf-8")
        )
        intermediate = load_certificate(INTERMEDIATE_CERT)

        if certificate.issuer != intermediate.subject:
            return False

        verify_certificate_signature(intermediate, certificate)
        return True
    except Exception:
        return False


def remove_user_certificate(username: str) -> None:
    path = ISSUED_DIR / f"{username}.crt"
    if path.exists():
        path.unlink()


def verify_certificate_signature(
    issuer_cert,
    child_cert
):

    issuer_public_key = issuer_cert.public_key()

    issuer_public_key.verify(

        child_cert.signature,

        child_cert.tbs_certificate_bytes,

        padding.PKCS1v15(),

        child_cert.signature_hash_algorithm,

    )

    return True

def verify_chain():

    root = load_certificate(
        ROOT_CERT
    )

    intermediate = load_certificate(
        INTERMEDIATE_CERT
    )

    verify_certificate_signature(
        root,
        intermediate
    )

    print(
        "Certificate Chain VALID."
    )

    return True
# ============================================================
# User Key
# ============================================================

def generate_user_keypair():

    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=4096,

    )

    return private_key

def save_user_private_key(

    username: str,

    private_key,

):

    path = ISSUED_DIR / f"{username}.key"

    save_private_key(

        path,

        private_key

    )

    return path
def load_user_private_key(

    username: str,

):

    path = ISSUED_DIR / f"{username}.key"

    return load_private_key(path)
# ============================================================
# CSR
# ============================================================

def generate_csr(

    username: str,

    private_key,

):

    csr = (

        x509.CertificateSigningRequestBuilder()

        .subject_name(

            x509.Name([

                x509.NameAttribute(

                    NameOID.COUNTRY_NAME,

                    "ID"

                ),

                x509.NameAttribute(

                    NameOID.ORGANIZATION_NAME,

                    "ONE_MIND"

                ),

                x509.NameAttribute(

                    NameOID.COMMON_NAME,

                    username

                ),

            ])

        )

        .sign(

            private_key,

            hashes.SHA512()

        )

    )

    return csr

def save_csr(

    username: str,

    csr,

):

    path = CSR_DIR / f"{username}.csr"

    path.write_bytes(

        csr.public_bytes(

            serialization.Encoding.PEM

        )

    )

    return path

def load_csr(

    username: str,

):

    path = CSR_DIR / f"{username}.csr"

    return x509.load_pem_x509_csr(

        path.read_bytes()

    )

# ============================================================
# Issue Certificate
# ============================================================

def issue_certificate(

    username: str,

    public_key_pem: str,

):

    public_key = serialization.load_pem_public_key(

        public_key_pem.encode("utf-8")

    )

    intermediate_key = load_private_key(

        INTERMEDIATE_KEY

    )

    intermediate_cert = load_certificate(

        INTERMEDIATE_CERT

    )

    certificate = (

        x509.CertificateBuilder()

        .subject_name(

            x509.Name(

                [

                    x509.NameAttribute(

                        NameOID.COUNTRY_NAME,

                        "ID"

                    ),

                    x509.NameAttribute(

                        NameOID.ORGANIZATION_NAME,

                        "ONE_MIND"

                    ),

                    x509.NameAttribute(

                        NameOID.COMMON_NAME,

                        username

                    ),

                ]

            )

        )

        .issuer_name(

            intermediate_cert.subject

        )

        .public_key(

            public_key

        )

        .serial_number(

            x509.random_serial_number()

        )

        .not_valid_before(

            datetime.now(timezone.utc)

        )

        .not_valid_after(

            datetime.now(timezone.utc)

            + timedelta(days=365)

        )

        .add_extension(

            x509.BasicConstraints(

                ca=False,

                path_length=None

            ),

            critical=True,

        )

        .add_extension(

            x509.KeyUsage(

                digital_signature=True,

                key_encipherment=True,

                content_commitment=False,

                data_encipherment=False,

                key_agreement=False,

                key_cert_sign=False,

                crl_sign=False,

                encipher_only=False,

                decipher_only=False,

            ),

            critical=True,

        )

        .sign(

            intermediate_key,

            hashes.SHA512()

        )

    )

    path = ISSUED_DIR / f"{username}.crt"

    save_certificate(

        path,

        certificate

    )

    return path

def load_user_certificate(

    username: str,

):

    path = ISSUED_DIR / f"{username}.crt"

    return load_certificate(path)
