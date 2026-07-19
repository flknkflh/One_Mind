import base64
import hashlib
import json
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from app import main
from app.auth import passwords


class PasswordBaselineTests(unittest.TestCase):
    @staticmethod
    def legacy_hash(password: str) -> str:
        salt = b"legacy-test-salt"
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            passwords.LEGACY_PBKDF2_ITERATIONS,
        )
        salt_text = base64.b64encode(salt).decode("ascii")
        digest_text = base64.b64encode(digest).decode("ascii")
        return (
            f"pbkdf2_sha256${passwords.LEGACY_PBKDF2_ITERATIONS}$"
            f"{salt_text}${digest_text}"
        )

    def test_password_hash_round_trip(self):
        encoded = main.hash_password("contoh-password-kuat")

        self.assertTrue(main.verify_password("contoh-password-kuat", encoded))
        self.assertFalse(main.verify_password("password-salah", encoded))
        self.assertTrue(encoded.startswith("$argon2id$"))

    def test_argon2id_uses_unique_salt(self):
        first = main.hash_password("contoh-password-kuat")
        second = main.hash_password("contoh-password-kuat")

        self.assertNotEqual(first, second)
        self.assertTrue(main.verify_password("contoh-password-kuat", first))
        self.assertTrue(main.verify_password("contoh-password-kuat", second))

    def test_malformed_password_hash_is_rejected(self):
        self.assertFalse(main.verify_password("password", "bukan-hash-valid"))

    def test_legacy_pbkdf2_is_migrated_to_argon2id(self):
        legacy = self.legacy_hash("password-lama-yang-kuat")

        valid, replacement = passwords.verify_and_rehash(
            "password-lama-yang-kuat",
            legacy,
        )

        self.assertTrue(valid)
        self.assertIsNotNone(replacement)
        self.assertTrue(replacement.startswith("$argon2id$"))
        self.assertTrue(main.verify_password("password-lama-yang-kuat", replacement))

    def test_admin_login_persists_legacy_rehash(self):
        username = "legacy-admin"
        password = "password-lama-yang-kuat"
        conn = main.db()
        conn.execute("DELETE FROM administrators WHERE username=?", (username,))
        conn.execute(
            "INSERT INTO administrators (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, self.legacy_hash(password), main.now_iso()),
        )
        conn.commit()
        conn.close()

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/admin/login",
                "headers": [],
                "client": ("127.0.0.1", 12345),
            }
        )
        result = main.admin_login(
            main.AdminLoginIn(username=username, password=password),
            request,
        )

        conn = main.db()
        stored = conn.execute(
            "SELECT password_hash FROM administrators WHERE username=?",
            (username,),
        ).fetchone()["password_hash"]
        conn.close()

        self.assertEqual(result["username"], username)
        self.assertTrue(stored.startswith("$argon2id$"))

    def test_user_login_persists_legacy_rehash(self):
        username = "legacy-user"
        password = "password-lama-yang-kuat"
        conn = main.db()
        conn.execute("DELETE FROM users WHERE username=?", (username,))
        conn.execute(
            """
            INSERT INTO users (
                username, display_name, password_hash, nip, rank, position,
                public_key, pki_public_key, account_status,
                certificate_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'NONE', ?)
            """,
            (
                username,
                username,
                self.legacy_hash(password),
                "NIP-LEGACY",
                "TEST",
                "TEST",
                json.dumps({"algorithm": "test"}),
                "PUBLIC-KEY-PLACEHOLDER",
                main.now_iso(),
            ),
        )
        conn.commit()
        conn.close()

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/login",
                "headers": [],
                "client": ("127.0.0.1", 12346),
            }
        )
        result = main.login(
            main.LoginIn(username=username, password=password),
            request,
        )

        conn = main.db()
        stored = conn.execute(
            "SELECT password_hash FROM users WHERE username=?",
            (username,),
        ).fetchone()["password_hash"]
        conn.close()

        self.assertEqual(result["username"], username)
        self.assertTrue(stored.startswith("$argon2id$"))

    def test_new_password_policy_rejects_short_password(self):
        with self.assertRaises(ValidationError):
            main.AdminSetupIn(username="admin-office", password="pendek123")


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
