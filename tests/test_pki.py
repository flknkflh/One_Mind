import base64
import json
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from app import main
from app.pki import pki


class PKIRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pki.initialize_pki(auto_init=True)

    def setUp(self):
        self.conn = main.db()
        self.conn.execute("DELETE FROM certificate_challenges")
        self.conn.execute("DELETE FROM certificates")
        self.conn.execute("DELETE FROM users")
        self.conn.execute("DELETE FROM system_metadata")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    @staticmethod
    def make_user_keypair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return private_key, public_key_pem

    def insert_user(self, username: str, public_key_pem: str, status: str):
        self.conn.execute(
            """
            INSERT INTO users (
                username, display_name, password_hash, nip, rank, position,
                public_key, pki_public_key, account_status,
                certificate_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
            """,
            (
                username,
                username,
                main.hash_password("password-test-yang-kuat"),
                "NIP-TEST",
                "TEST",
                "TEST",
                json.dumps({"algorithm": "test"}),
                public_key_pem,
                status,
                main.now_iso(),
            ),
        )

    def insert_certificate(
        self,
        username: str,
        certificate_pem: str,
        status: str = "ACTIVE",
    ):
        certificate = x509.load_pem_x509_certificate(
            certificate_pem.encode("utf-8")
        )
        self.conn.execute(
            """
            INSERT INTO certificates (
                serial_number, username, certificate_pem,
                issued_at, expires_at, status
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                format(certificate.serial_number, "X"),
                username,
                certificate_pem,
                certificate.not_valid_before_utc.isoformat(),
                certificate.not_valid_after_utc.isoformat(),
                status,
            ),
        )
        return format(certificate.serial_number, "X")

    @staticmethod
    def make_foreign_certificate(username: str, public_key) -> str:
        issuer_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        issuer_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "CA Lama")]
        )
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
            )
            .issuer_name(issuer_name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(issuer_key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def test_certificate_from_current_intermediate_remains_active(self):
        _, public_key_pem = self.make_user_keypair()
        self.insert_user("valid-user", public_key_pem, "ISSUED")
        certificate_path = pki.issue_certificate("valid-user", public_key_pem)
        certificate_pem = certificate_path.read_text(encoding="utf-8")
        serial = self.insert_certificate("valid-user", certificate_pem)
        self.conn.commit()

        replaced = main.reconcile_certificates_after_ca_rotation(self.conn)
        self.conn.commit()

        row = self.conn.execute(
            "SELECT status FROM certificates WHERE serial_number=?",
            (serial,),
        ).fetchone()
        self.assertEqual(replaced, 0)
        self.assertEqual(row["status"], "ACTIVE")

    def test_foreign_certificate_is_marked_replaced(self):
        private_key, public_key_pem = self.make_user_keypair()
        self.insert_user("rotated-user", public_key_pem, "ISSUED")
        certificate_pem = self.make_foreign_certificate(
            "rotated-user",
            private_key.public_key(),
        )
        serial = self.insert_certificate("rotated-user", certificate_pem)
        self.conn.commit()

        replaced = main.reconcile_certificates_after_ca_rotation(self.conn)
        self.conn.commit()

        certificate = self.conn.execute(
            "SELECT status FROM certificates WHERE serial_number=?",
            (serial,),
        ).fetchone()
        user = self.conn.execute(
            "SELECT certificate_status FROM users WHERE username='rotated-user'"
        ).fetchone()
        metadata = self.conn.execute(
            "SELECT value FROM system_metadata WHERE key='pki_intermediate_fingerprint'"
        ).fetchone()

        self.assertEqual(replaced, 1)
        self.assertEqual(certificate["status"], "REPLACED")
        self.assertEqual(user["certificate_status"], "NONE")
        self.assertEqual(metadata["value"], pki.intermediate_ca_fingerprint())

    def test_replaced_certificate_is_reissued_after_valid_rsa_proof(self):
        private_key, public_key_pem = self.make_user_keypair()
        username = "reissue-user"
        nonce = "nonce-untuk-reissue"
        self.insert_user(username, public_key_pem, "NONE")
        old_certificate = self.make_foreign_certificate(
            username,
            private_key.public_key(),
        )
        self.insert_certificate(username, old_certificate, "REPLACED")
        self.conn.execute(
            "INSERT INTO certificate_challenges (username, nonce, created_at) VALUES (?, ?, ?)",
            (username, nonce, main.now_iso()),
        )
        self.conn.commit()

        signature = private_key.sign(
            nonce.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA512(),
        )
        result = main.login_verify(
            main.LoginVerifyIn(
                nonce=nonce,
                signature=base64.b64encode(signature).decode("ascii"),
                public_key_pem=public_key_pem,
            ),
            username=username,
        )

        active = self.conn.execute(
            "SELECT COUNT(*) AS total FROM certificates WHERE username=? AND status='ACTIVE'",
            (username,),
        ).fetchone()
        self.assertTrue(result["certificate_issued"])
        self.assertEqual(result["certificate_status"], "ISSUED")
        self.assertEqual(active["total"], 1)


if __name__ == "__main__":
    unittest.main()
