import json
import unittest

from fastapi import HTTPException

from app import main
from tests.dipp_helpers import b64url, make_user_material, wrapped_key


class DippEphemeralServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.materials = {
            username: make_user_material(username)
            for username in ("alice", "bob")
        }

    def setUp(self):
        self.conn = main.db()
        self.conn.execute("DELETE FROM dipp_ciphertexts")
        self.conn.execute("DELETE FROM file_requests")
        self.conn.execute("DELETE FROM shares")
        self.conn.execute("DELETE FROM files")
        self.conn.execute("DELETE FROM users")
        for username, (public_identity, _, signing_public_pem) in self.materials.items():
            self.conn.execute(
                """
                INSERT INTO users (
                    username, display_name, password_hash, nip, rank, position,
                    public_key, pki_public_key, account_status,
                    certificate_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'NONE', ?)
                """,
                (
                    username,
                    username.title(),
                    main.hash_password("password-test-yang-kuat"),
                    f"NIP-{username}",
                    "TEST",
                    "TEST",
                    json.dumps(public_identity),
                    signing_public_pem,
                    main.now_iso(),
                ),
            )
        self.conn.commit()

    def tearDown(self):
        self.conn.execute("DELETE FROM dipp_ciphertexts")
        self.conn.execute("DELETE FROM users")
        self.conn.commit()
        self.conn.close()

    def envelope(self, marker: str = "valid") -> dict:
        return wrapped_key(
            "alice",
            "bob",
            self.materials["bob"][0],
            self.materials["alice"][1],
            marker,
        )

    def test_authenticated_ciphertext_is_registered_without_secret_geometry(self):
        envelope = self.envelope()
        main.register_dipp_ciphertext(self.conn, envelope, "alice", "bob")
        self.conn.commit()

        row = self.conn.execute("SELECT * FROM dipp_ciphertexts").fetchone()
        columns = {
            item["name"]
            for item in self.conn.execute("PRAGMA table_info(dipp_ciphertexts)").fetchall()
        }
        self.assertEqual(row["session_id"], envelope["session_id"])
        self.assertEqual(row["recipient_key_id"], self.materials["bob"][0]["key_id"])
        self.assertFalse(columns & {"x_b", "r_i", "pre_key", "session_key", "file_key", "U", "V"})

    def test_replay_session_and_transcript_are_rejected(self):
        envelope = self.envelope("replay")
        main.register_dipp_ciphertext(self.conn, envelope, "alice", "bob")
        with self.assertRaises(HTTPException) as replay:
            main.register_dipp_ciphertext(self.conn, envelope, "alice", "bob")
        self.assertEqual(replay.exception.status_code, 409)

    def test_transcript_tamper_and_bad_signature_are_rejected(self):
        changed = self.envelope("changed")
        changed["dipp_components"][0]["V"] += 1
        with self.assertRaises(HTTPException) as transcript:
            main.register_dipp_ciphertext(self.conn, changed, "alice", "bob")
        self.assertEqual(transcript.exception.status_code, 400)

        bad_signature = self.envelope("bad-signature")
        bad_signature["sender_signature"] = b64url(bytes(512))
        with self.assertRaises(HTTPException) as signature:
            main.register_dipp_ciphertext(self.conn, bad_signature, "alice", "bob")
        self.assertEqual(signature.exception.status_code, 400)

    def test_recipient_public_material_substitution_is_rejected(self):
        envelope = self.envelope("substitution")
        envelope["B_b"] = self.materials["alice"][0]["B_b"]
        with self.assertRaises(HTTPException) as substitution:
            main.register_dipp_ciphertext(self.conn, envelope, "alice", "bob")
        self.assertEqual(substitution.exception.status_code, 400)

    def test_direct_aes_key_schema_is_rejected_by_hkdf_profile(self):
        envelope = self.envelope("obsolete-direct")
        envelope.pop("key_establishment_algorithm")
        envelope.pop("wrap_algorithm")
        envelope.pop("wrap_nonce")
        envelope.pop("wrapped_file_key")
        envelope["algorithms"] = {
            "geometry": main.DIPP_GEOMETRY_PROFILE,
            "functional": "NORMALIZED-AVERAGE-DISTANCE-v1",
            "reconciliation": "TWO-CENTER-MOD-Q-v1",
            "key_wrapping": "DIPP-ER-DIRECT-256-BIT-v1",
        }
        envelope["key_wrapping_algorithm"] = "DIPP-ER-DIRECT-256-BIT-v1"
        with self.assertRaises(HTTPException) as obsolete:
            main.validate_dipp_wrapped_key(envelope)
        self.assertEqual(obsolete.exception.status_code, 400)

    def test_coordinate_outside_profile_domain_is_rejected(self):
        envelope = self.envelope("coordinate-bound")
        coordinate = (main.DIPP_MAX_COORDINATE_ABS + 1).to_bytes(
            4,
            "big",
            signed=True,
        )
        envelope["dipp_components"][0]["U"] = b64url(
            coordinate + bytes(main.DIPP_VECTOR_BYTES - 4)
        )
        with self.assertRaises(HTTPException) as bounded:
            main.validate_dipp_wrapped_key(envelope)
        self.assertEqual(bounded.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
