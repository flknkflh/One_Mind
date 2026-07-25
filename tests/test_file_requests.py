import json
import shutil
import unittest

from fastapi import HTTPException

from app import main
from tests.dipp_helpers import b64url, make_user_material, wrapped_key


class FileRequestTests(unittest.TestCase):
    def setUp(self):
        self.conn = main.db()
        self._clear_data()
        self.materials = {}
        for username in ("alice", "bob", "charlie"):
            public_identity, signing_private, signing_public_pem = make_user_material(username)
            self.materials[username] = (public_identity, signing_private)
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
        self._clear_data()
        self.conn.close()

    def _clear_data(self):
        self.conn.execute("DELETE FROM dipp_ciphertexts")
        self.conn.execute("DELETE FROM file_requests")
        self.conn.execute("DELETE FROM shares")
        self.conn.execute("DELETE FROM files")
        self.conn.execute("DELETE FROM upload_sessions")
        self.conn.execute("DELETE FROM certificate_requests")
        self.conn.execute("DELETE FROM certificate_challenges")
        self.conn.execute("DELETE FROM certificate_revocation")
        self.conn.execute("DELETE FROM certificates")
        self.conn.execute("DELETE FROM users")
        self.conn.commit()
        shutil.rmtree(main.STORAGE_DIR, ignore_errors=True)
        main.STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    def dipp_wrapped_key(
        self,
        receiver: str,
        marker: str = "test",
        file_context_id: str | None = None,
    ) -> dict:
        return wrapped_key(
            "alice",
            receiver,
            self.materials[receiver][0],
            self.materials["alice"][1],
            marker,
            file_context_id,
        )

    def insert_file(self, file_id: str, *, hidden: bool):
        file_context_id = b64url(file_id.encode().ljust(24, b"0")[:24])
        self.conn.execute(
            """
            INSERT INTO files (
                id, owner, filename, envelope_name,
                encrypted_size, is_hidden, created_at
            ) VALUES (?, 'alice', ?, ?, 2048, ?, ?)
            """,
            (
                file_id,
                f"{file_id}.txt",
                f"{file_id}.json",
                int(hidden),
                main.now_iso(),
            ),
        )
        self.conn.execute(
            """
            INSERT INTO shares (
                id, file_id, owner, recipient,
                wrapped_key, permission, created_at
            ) VALUES (?, ?, 'alice', 'alice', ?, 'owner', ?)
            """,
            (
                f"share-{file_id}",
                file_id,
                json.dumps({"wrapped": "owner-key"}),
                main.now_iso(),
            ),
        )
        self.conn.commit()
        main.envelope_path(file_id).write_text(
            json.dumps({"file_context_id": file_context_id}),
            encoding="utf-8",
        )
        return file_context_id

    def test_catalog_exposes_only_visible_metadata(self):
        self.insert_file("visible-file", hidden=False)
        self.insert_file("hidden-file", hidden=True)

        catalog = main.file_catalog(username="bob")

        self.assertEqual([item["id"] for item in catalog], ["visible-file"])
        self.assertNotIn("envelope", catalog[0])
        self.assertNotIn("wrapped_key", catalog[0])
        self.assertFalse(catalog[0]["has_access"])

    def test_request_requires_visible_file_and_cannot_duplicate(self):
        self.insert_file("visible-file", hidden=False)
        self.insert_file("hidden-file", hidden=True)

        created = main.create_file_request("visible-file", username="bob")
        self.assertEqual(created["status"], "PENDING")

        with self.assertRaises(HTTPException) as duplicate:
            main.create_file_request("visible-file", username="bob")
        self.assertEqual(duplicate.exception.status_code, 409)

        with self.assertRaises(HTTPException) as hidden:
            main.create_file_request("hidden-file", username="bob")
        self.assertEqual(hidden.exception.status_code, 404)

    def test_only_owner_can_approve_and_share_is_viewer(self):
        file_context_id = self.insert_file("visible-file", hidden=False)
        request_id = main.create_file_request(
            "visible-file",
            username="bob",
        )["id"]
        approval = main.FileRequestApprovalIn(
            wrapped_key=self.dipp_wrapped_key("bob", "bob", file_context_id),
        )

        with self.assertRaises(HTTPException) as unauthorized:
            main.approve_file_request(request_id, approval, username="charlie")
        self.assertEqual(unauthorized.exception.status_code, 403)

        result = main.approve_file_request(request_id, approval, username="alice")
        self.assertEqual(result["status"], "APPROVED")

        share = self.conn.execute(
            "SELECT permission, wrapped_key FROM shares WHERE file_id=? AND recipient='bob'",
            ("visible-file",),
        ).fetchone()
        request_row = self.conn.execute(
            "SELECT status FROM file_requests WHERE id=?",
            (request_id,),
        ).fetchone()
        self.assertEqual(share["permission"], "viewer")
        self.assertEqual(
            json.loads(share["wrapped_key"])["version"],
            main.DIPP_ENVELOPE_VERSION,
        )
        self.assertEqual(request_row["status"], "APPROVED")

    def test_hiding_file_cancels_pending_requests(self):
        self.insert_file("visible-file", hidden=False)
        request_id = main.create_file_request(
            "visible-file",
            username="bob",
        )["id"]

        result = main.update_file_visibility(
            "visible-file",
            main.FileVisibilityIn(is_hidden=True),
            username="alice",
        )

        request_row = self.conn.execute(
            "SELECT status FROM file_requests WHERE id=?",
            (request_id,),
        ).fetchone()
        self.assertTrue(result["is_hidden"])
        self.assertEqual(result["cancelled_requests"], 1)
        self.assertEqual(request_row["status"], "CANCELLED")
        self.assertEqual(main.file_catalog(username="bob"), [])


if __name__ == "__main__":
    unittest.main()
