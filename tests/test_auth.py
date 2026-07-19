import base64
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException

from app import main


class PasswordBaselineTests(unittest.TestCase):
    def test_password_hash_round_trip(self):
        encoded = main.hash_password("contoh-password-kuat")

        self.assertTrue(main.verify_password("contoh-password-kuat", encoded))
        self.assertFalse(main.verify_password("password-salah", encoded))
        self.assertTrue(encoded.startswith("pbkdf2_sha256$"))

    def test_malformed_password_hash_is_rejected(self):
        self.assertFalse(main.verify_password("password", "bukan-hash-valid"))


class SessionTokenBaselineTests(unittest.TestCase):
    def test_user_token_round_trip_and_tamper_rejection(self):
        token = main.sign_token("alice")

        self.assertEqual(main.verify_token(token), "alice")

        raw, signature = token.split(".", 1)
        replacement = "0" if signature[-1] != "0" else "1"
        tampered = f"{raw}.{signature[:-1]}{replacement}"

        with self.assertRaises(HTTPException) as raised:
            main.verify_token(tampered)

        self.assertEqual(raised.exception.status_code, 401)

    def test_pending_token_cannot_be_used_as_user_token(self):
        pending_token = main.sign_pending_login_token("alice")
        self.assertEqual(main.verify_pending_login_token(pending_token), "alice")

        with self.assertRaises(HTTPException) as raised:
            main.verify_token(pending_token)

        self.assertEqual(raised.exception.status_code, 401)

    def test_admin_token_cannot_be_used_as_user_token(self):
        admin_token = main.sign_admin_token("root-admin")
        self.assertEqual(main.verify_admin_token(admin_token), "root-admin")

        with self.assertRaises(HTTPException) as raised:
            main.verify_token(admin_token)

        self.assertEqual(raised.exception.status_code, 401)


class RSAPossessionBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        cls.public_key_pem = cls.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def test_valid_signature_is_accepted(self):
        nonce = "nonce-login-yang-unik"
        signature = self.private_key.sign(
            nonce.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA512(),
        )

        self.assertTrue(
            main.verify_pki_signature(
                self.public_key_pem,
                nonce,
                base64.b64encode(signature).decode("ascii"),
            )
        )

    def test_signature_for_different_nonce_is_rejected(self):
        signature = self.private_key.sign(
            b"nonce-asli",
            padding.PKCS1v15(),
            hashes.SHA512(),
        )

        self.assertFalse(
            main.verify_pki_signature(
                self.public_key_pem,
                "nonce-yang-diubah",
                base64.b64encode(signature).decode("ascii"),
            )
        )


if __name__ == "__main__":
    unittest.main()
