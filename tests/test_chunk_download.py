import base64
import hashlib
import json
import shutil
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException

from app import main
from tests.dipp_helpers import b64url, make_user_material, wrapped_key


class ChunkDownloadTests(unittest.TestCase):
    def setUp(self):
        self.conn = main.db()
        self._clear_runtime()
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
        self._clear_runtime()
        self.conn.close()

    def _clear_runtime(self):
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
        shutil.rmtree(main.TEMP_UPLOAD_DIR, ignore_errors=True)
        main.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        main.TEMP_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    def dipp_wrapped_key(
        self,
        receiver: str,
        marker: str = "test",
        file_context_id: str | None = None,
    ) -> dict:
        recipient_public = self.materials[receiver][0]
        sender_private = self.materials["alice"][1]
        return wrapped_key(
            "alice", receiver, recipient_public, sender_private, marker, file_context_id
        )

    @staticmethod
    def encrypted_payload(plaintext: bytes, filename: str = "besar.bin"):
        key = AESGCM.generate_key(bit_length=256)
        iv = bytes(range(12))
        aad = json.dumps(
            {"filename": filename, "type": "application/octet-stream"},
            separators=(",", ":"),
        ).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(iv, plaintext, aad)
        envelope = {
            "version": 2,
            "algorithm": "AES-256-GCM",
            "protocol_version": main.DIPP_FILE_PROTOCOL_VERSION,
            "file_context_id": b64url(hashlib.sha256(plaintext).digest()[:24]),
            "filename": filename,
            "mime": "application/octet-stream",
            "aad_b64": base64.b64encode(aad).decode("ascii"),
            "iv_b64": base64.b64encode(iv).decode("ascii"),
        }
        return key, ciphertext, envelope

    def upload_ciphertext(
        self,
        ciphertext: bytes,
        envelope: dict,
        *,
        chunk_size: int = 17,
        finish: bool = True,
        hash_override: str | None = None,
    ):
        chunks = [
            ciphertext[offset:offset + chunk_size]
            for offset in range(0, len(ciphertext), chunk_size)
        ]
        session = main.upload_start(
            main.UploadStartIn(
                filename="besar.bin",
                file_size=len(ciphertext),
                chunk_size=chunk_size,
                total_chunks=len(chunks),
            ),
            username="alice",
        )
        for index, chunk in enumerate(chunks):
            main.upload_chunk(
                main.UploadChunkIn(
                    upload_id=session["upload_id"],
                    chunk_index=index,
                    total_chunks=len(chunks),
                    data_b64=base64.b64encode(chunk).decode("ascii"),
                ),
                username="alice",
            )
        if not finish:
            return session, chunks
        digest = base64.b64encode(hashlib.sha256(ciphertext).digest()).decode("ascii")
        result = main.upload_finish(
            main.UploadFinishIn(
                upload_id=session["upload_id"],
                envelope=envelope,
                wrapped_key_for_owner=self.dipp_wrapped_key(
                    "alice", "owner", envelope["file_context_id"]
                ),
                ciphertext_sha256=hash_override or digest,
                is_hidden=True,
            ),
            username="alice",
        )
        return result, chunks

    @staticmethod
    def read_download_chunks(file_id: str, total_chunks: int, username: str):
        parts = []
        for index in range(total_chunks):
            response = main.download_file_chunk(file_id, index, username=username)
            parts.append(Path(response.path).read_bytes())
            assert response.headers["x-chunk-index"] == str(index)
            assert response.headers["x-total-chunks"] == str(total_chunks)
        return b"".join(parts)

    def test_chunked_upload_download_and_aes_gcm_decrypt(self):
        plaintext = (b"ONE_MIND-CHUNK-" * 20) + b"selesai"
        key, ciphertext, envelope = self.encrypted_payload(plaintext)
        uploaded, chunks = self.upload_ciphertext(ciphertext, envelope)
        file_id = uploaded["file_id"]

        detail = main.download_file(file_id, username="alice")
        stored_envelope = json.loads(main.envelope_path(file_id).read_text("utf-8"))
        downloaded = self.read_download_chunks(file_id, len(chunks), "alice")

        self.assertEqual(uploaded["storage_format"], "chunked-v1")
        self.assertNotIn("ciphertext_b64", detail["envelope"])
        self.assertNotIn("ciphertext_b64", stored_envelope)
        self.assertEqual(detail["download"]["storage_format"], "chunked-v1")
        self.assertEqual(detail["download"]["total_chunks"], len(chunks))
        self.assertEqual(detail["download"]["ciphertext_size"], len(ciphertext))
        self.assertEqual(downloaded, ciphertext)
        self.assertEqual(AESGCM(key).decrypt(
            base64.b64decode(envelope["iv_b64"]),
            downloaded,
            base64.b64decode(envelope["aad_b64"]),
        ), plaintext)

    def test_chunk_authorization_bounds_and_revoke(self):
        _, ciphertext, envelope = self.encrypted_payload(b"otorisasi" * 20)
        uploaded, chunks = self.upload_ciphertext(ciphertext, envelope)
        file_id = uploaded["file_id"]

        with self.assertRaises(HTTPException) as unauthorized:
            main.download_file_chunk(file_id, 0, username="bob")
        self.assertEqual(unauthorized.exception.status_code, 404)

        with self.assertRaises(HTTPException) as out_of_range:
            main.download_file_chunk(file_id, len(chunks), username="alice")
        self.assertEqual(out_of_range.exception.status_code, 416)

        main.share_file(
            main.ShareIn(
                file_id=file_id,
                recipient="bob",
                wrapped_key=self.dipp_wrapped_key(
                    "bob", "bob", envelope["file_context_id"]
                ),
                permission="viewer",
            ),
            username="alice",
        )
        main.download_file_chunk(file_id, 0, username="bob")
        main.revoke_share(file_id, "bob", username="alice")

        with self.assertRaises(HTTPException) as revoked:
            main.download_file_chunk(file_id, 0, username="bob")
        self.assertEqual(revoked.exception.status_code, 404)

    def test_finish_rejects_missing_chunk_and_bad_hash(self):
        _, ciphertext, envelope = self.encrypted_payload(b"integritas" * 20)
        chunk_size = 19
        total_chunks = (len(ciphertext) + chunk_size - 1) // chunk_size
        session = main.upload_start(
            main.UploadStartIn(
                filename="besar.bin",
                file_size=len(ciphertext),
                chunk_size=chunk_size,
                total_chunks=total_chunks,
            ),
            username="alice",
        )
        first_chunk = ciphertext[:chunk_size]
        main.upload_chunk(
            main.UploadChunkIn(
                upload_id=session["upload_id"],
                chunk_index=0,
                total_chunks=total_chunks,
                data_b64=base64.b64encode(first_chunk).decode("ascii"),
            ),
            username="alice",
        )
        with self.assertRaises(HTTPException) as missing:
            main.upload_finish(
                main.UploadFinishIn(
                    upload_id=session["upload_id"],
                    envelope=envelope,
                    wrapped_key_for_owner=self.dipp_wrapped_key(
                        "alice", "owner-retry", envelope["file_context_id"]
                    ),
                    ciphertext_sha256=base64.b64encode(
                        hashlib.sha256(ciphertext).digest()
                    ).decode("ascii"),
                ),
                username="alice",
            )
        self.assertEqual(missing.exception.status_code, 409)

        with self.assertRaises(HTTPException) as bad_hash:
            self.upload_ciphertext(
                ciphertext,
                envelope,
                hash_override=base64.b64encode(b"0" * 32).decode("ascii"),
            )
        self.assertEqual(bad_hash.exception.status_code, 409)

    def test_update_rewrites_chunks_and_delete_cleans_storage(self):
        _, ciphertext, envelope = self.encrypted_payload(b"versi-awal" * 20)
        uploaded, _ = self.upload_ciphertext(ciphertext, envelope)
        file_id = uploaded["file_id"]

        replacement_plaintext = b"versi-pengganti" * 30
        replacement_key, replacement, replacement_envelope = self.encrypted_payload(
            replacement_plaintext,
            "pengganti.bin",
        )
        replacement_envelope["file_id"] = file_id
        replacement_envelope["version"] = 2
        replacement_envelope["ciphertext_b64"] = base64.b64encode(
            replacement
        ).decode("ascii")
        result = main.update_file(
            file_id,
            main.FileUpdateIn(
                filename="pengganti.bin",
                envelope=replacement_envelope,
                wrapped_keys=[
                    main.WrappedKeyIn(
                        recipient="alice",
                        wrapped_key=self.dipp_wrapped_key(
                            "alice", "owner-v2", replacement_envelope["file_context_id"]
                        ),
                    )
                ],
            ),
            username="alice",
        )

        downloaded = self.read_download_chunks(
            file_id,
            result["total_chunks"],
            "alice",
        )
        self.assertEqual(downloaded, replacement)
        self.assertEqual(
            len(list(main.file_storage_dir(file_id).glob("chunk_*.bin"))),
            result["total_chunks"],
        )
        self.assertEqual(
            AESGCM(replacement_key).decrypt(
                base64.b64decode(replacement_envelope["iv_b64"]),
                downloaded,
                base64.b64decode(replacement_envelope["aad_b64"]),
            ),
            replacement_plaintext,
        )
        storage_dir = main.file_storage_dir(file_id, create_parent=False)
        self.assertTrue(storage_dir.is_dir())
        main.delete_file(file_id, username="alice")
        self.assertFalse(storage_dir.exists())


if __name__ == "__main__":
    unittest.main()
