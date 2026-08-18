import ast
import asyncio
import base64
import hashlib
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from app import main
from tests.dipp_helpers import b64url, make_user_material, wrapped_key


class SqlInjectionRegressionTests(unittest.TestCase):
    def test_sql_statements_are_static_literals(self):
        source_path = Path(main.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        unsafe = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            if not (
                isinstance(function, ast.Attribute)
                and function.attr in {"execute", "executemany", "executescript"}
            ):
                continue
            if not isinstance(node.args[0], ast.Constant) or not isinstance(
                node.args[0].value, str
            ):
                unsafe.append(node.lineno)

        self.assertEqual(
            unsafe,
            [],
            f"SQL dinamis ditemukan pada baris {unsafe}; gunakan SQL literal dan parameter binding.",
        )

    def test_sql_injection_payload_is_rejected_as_username(self):
        with self.assertRaises(ValidationError):
            main.LoginIn(username="alice' OR 1=1 --", password="password")


class RestrictedInputTests(unittest.TestCase):
    @staticmethod
    def request(method: str, path: str, query: bytes = b"", headers=()):
        return Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": method,
                "scheme": "https",
                "path": path,
                "raw_path": path.encode("ascii"),
                "query_string": query,
                "headers": list(headers),
                "client": ("127.0.0.1", 12345),
                "server": ("testserver", 443),
                "root_path": "",
            }
        )

    def test_api_rejects_unknown_query_and_wrong_content_type(self):
        async def should_not_run(_request):
            self.fail("Request tidak boleh mencapai endpoint.")

        query_response = asyncio.run(
            main.security_headers(
                self.request("GET", "/api/users", b"unexpected=value"),
                should_not_run,
            )
        )
        self.assertEqual(query_response.status_code, 400)

        content_type_response = asyncio.run(
            main.security_headers(
                self.request(
                    "POST",
                    "/api/login",
                    headers=(
                        (b"content-type", b"text/plain"),
                        (b"content-length", b"2"),
                    ),
                ),
                should_not_run,
            )
        )
        self.assertEqual(content_type_response.status_code, 415)

    def test_all_api_input_models_forbid_unknown_fields(self):
        for model in main.StrictInputModel.__subclasses__():
            with self.subTest(model=model.__name__):
                self.assertEqual(model.model_config.get("extra"), "forbid")
                self.assertIs(model.model_config.get("strict"), True)

        with self.assertRaises(ValidationError):
            main.LoginIn(
                username="alice",
                password="password",
                unexpected="not-allowed",
            )

    def test_api_models_do_not_coerce_numbers_or_booleans(self):
        with self.assertRaises(ValidationError):
            main.UploadStartIn(
                filename="payload.bin",
                file_size="1024",
                chunk_size=1024,
                total_chunks=1,
            )
        with self.assertRaises(ValidationError):
            main.FileVisibilityIn(is_hidden="yes")

    def test_personnel_metadata_rejects_markup(self):
        with self.assertRaises(ValidationError):
            main.AdminUserEditIn(
                display_name="<img src=x onerror=alert(1)>",
                nip="NIP-1",
                rank="Staff",
                position="Operator",
            )

    def test_filename_rejects_paths_and_windows_device_names(self):
        for filename in ("../database.sqlite3", r"..\database.sqlite3", "CON.txt"):
            with self.subTest(filename=filename), self.assertRaises(ValidationError):
                main.FileRenameIn(filename=filename)

    def test_upload_bounds_are_enforced(self):
        with self.assertRaises(ValidationError):
            main.UploadStartIn(
                filename="payload.bin",
                file_size=main.MAX_FILE_BYTES + 1,
                chunk_size=1024,
                total_chunks=1,
            )
        with self.assertRaises(ValidationError):
            main.UploadStartIn(
                filename="payload.bin",
                file_size=1024,
                chunk_size=main.MAX_CHUNK_BYTES + 1,
                total_chunks=1,
            )
        with self.assertRaises(ValidationError):
            main.UploadStartIn(
                filename="payload.bin",
                file_size=1024,
                chunk_size=1024,
                total_chunks=main.MAX_TOTAL_CHUNKS + 1,
            )

    def test_control_characters_are_rejected(self):
        with self.assertRaises(ValidationError):
            main.AdminUserEditIn(
                display_name="Alice\u0000Admin",
                nip="NIP-1",
                rank="Staff",
                position="Operator",
            )

    def test_authorization_header_has_a_hard_limit(self):
        with self.assertRaises(HTTPException) as caught:
            main.bearer_token(
                "Bearer " + ("a" * main.MAX_AUTHORIZATION_HEADER_BYTES),
                "Login diperlukan.",
            )
        self.assertEqual(caught.exception.status_code, 401)

    def test_public_identity_rejects_extra_fields(self):
        identity, _, _ = make_user_material("alice")
        identity["unexpected"] = "not-allowed"
        with self.assertRaises(HTTPException):
            main.validate_dipp_public_identity(identity, "alice")

    def test_file_envelope_is_canonical_and_metadata_bound(self):
        filename = "dokumen.txt"
        mime = "text/plain"
        envelope = {
            "version": 1,
            "algorithm": "AES-256-GCM",
            "protocol_version": main.DIPP_FILE_PROTOCOL_VERSION,
            "file_context_id": b64url(bytes(24)),
            "filename": filename,
            "mime": mime,
            "aad_b64": base64.b64encode(
                json.dumps(
                    {"filename": filename, "type": mime},
                    separators=(",", ":"),
                ).encode("utf-8")
            ).decode("ascii"),
            "iv_b64": base64.b64encode(bytes(12)).decode("ascii"),
        }
        main.validate_file_envelope(
            envelope,
            expected_filename=filename,
            expected_version=1,
            allow_ciphertext=False,
        )

        extra_field = envelope | {"unexpected": "not-allowed"}
        with self.assertRaises(HTTPException):
            main.validate_file_envelope(
                extra_field,
                expected_filename=filename,
                expected_version=1,
                allow_ciphertext=False,
            )

        mismatched_aad = envelope | {
            "aad_b64": base64.b64encode(
                b'{"filename":"other.txt","type":"text/plain"}'
            ).decode("ascii")
        }
        with self.assertRaises(HTTPException):
            main.validate_file_envelope(
                mismatched_aad,
                expected_filename=filename,
                expected_version=1,
                allow_ciphertext=False,
            )

        with self.assertRaises(HTTPException):
            main.validate_file_envelope(
                envelope | {"version": 999_999},
                expected_filename=filename,
                expected_version=1,
                allow_ciphertext=False,
            )

        with self.assertRaises(HTTPException):
            main.validate_file_envelope(
                envelope | {"uploaded_at": "\u0000<script>"},
                expected_filename=filename,
                expected_version=1,
                allow_ciphertext=False,
            )

    def test_key_id_domain_matches_current_browser_profile(self):
        source = (
            Path(main.__file__).parents[1] / "static" / "dipp_ephemeral_r.js"
        ).read_text(encoding="utf-8")
        domain = main.DIPP_KEY_ID_DOMAIN.decode("ascii")
        self.assertIn(f'utf8("{domain}")', source)

        identity, _, _ = make_user_material("alice")
        main.validate_dipp_public_identity(identity, "alice")
        seed = base64.urlsafe_b64decode(identity["public_seed"] + "==")
        vector = base64.urlsafe_b64decode(identity["B_b"] + "==")
        old_domain_identity = identity | {
            "key_id": hashlib.sha256(
                b"DIPP-ER-WEIGHTED-KEY-ID-v2"
                + b"alice"
                + seed
                + vector
            ).hexdigest()
        }
        with self.assertRaises(HTTPException):
            main.validate_dipp_public_identity(old_domain_identity, "alice")

    def test_wrapped_key_requires_canonical_session_id(self):
        identity, private_key, _ = make_user_material("alice")
        value = wrapped_key(
            "alice",
            "alice",
            identity,
            private_key,
            "canonical-session",
        )
        main.validate_dipp_wrapped_key(value)

        value["session_id"] = "<script>alert(1)</script>"
        transcript_hash = hashlib.sha256(
            main.canonical_json(main.dipp_transcript(value))
        ).digest()
        value["transcript_hash"] = b64url(transcript_hash)
        value["sender_signature"] = b64url(
            private_key.sign(
                transcript_hash,
                padding.PKCS1v15(),
                hashes.SHA512(),
            )
        )
        with self.assertRaises(HTTPException):
            main.validate_dipp_wrapped_key(value)


if __name__ == "__main__":
    unittest.main()
