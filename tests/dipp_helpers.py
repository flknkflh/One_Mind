import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import main


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_user_material(username: str) -> tuple[dict, object, str]:
    seed = hashlib.sha256(f"seed:{username}".encode()).digest()
    vector = b"".join(
        int(index + len(username)).to_bytes(4, "big", signed=True)
        for index in range(main.DIPP_VECTOR_BYTES // 4)
    )
    key_id = hashlib.sha256(
        b"DIPP-ER-WEIGHTED-KEY-ID-v2" + username.encode() + seed + vector
    ).hexdigest()
    public_identity = {
        "protocol": main.DIPP_PROTOCOL,
        "version": main.DIPP_PROTOCOL_VERSION,
        "type": "ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE_PUBLIC",
        "user_id": username,
        "key_id": key_id,
        "parameter_profile": main.DIPP_PARAMETER_SET,
        "public_seed": b64url(seed),
        "B_b": b64url(vector),
    }
    signing_private = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    signing_public_pem = signing_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return public_identity, signing_private, signing_public_pem


def wrapped_key(
    sender: str,
    recipient: str,
    recipient_public: dict,
    sender_signing_private,
    marker: str,
    file_context_id: str | None = None,
) -> dict:
    components = []
    for index in range(main.DIPP_COMPONENT_COUNT):
        vector = index.to_bytes(4, "big", signed=True) + bytes(main.DIPP_VECTOR_BYTES - 4)
        components.append({"U": b64url(vector), "V": index})
    transcript = {
        "version": main.DIPP_ENVELOPE_VERSION,
        "parameter_profile": main.DIPP_PARAMETER_SET,
        "sender_id": sender,
        "recipient_id": recipient,
        "recipient_key_id": recipient_public["key_id"],
        "public_seed": recipient_public["public_seed"],
        "B_b": recipient_public["B_b"],
        "session_id": f"session-{marker}",
        "file_context_id": file_context_id or b64url(
            hashlib.sha256(f"context:{marker}".encode()).digest()[:24]
        ),
        "dipp_components": components,
        "algorithms": {
            "geometry": main.DIPP_GEOMETRY_PROFILE,
            "extractor": "HKDF-SHA-256",
            "key_establishment": main.DIPP_KEY_ESTABLISHMENT,
        },
    }
    transcript_hash = hashlib.sha256(
        json.dumps(transcript, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).digest()
    signature = sender_signing_private.sign(
        transcript_hash,
        padding.PKCS1v15(),
        hashes.SHA512(),
    )
    return transcript | {
        "transcript_hash": b64url(transcript_hash),
        "key_establishment_algorithm": main.DIPP_KEY_ESTABLISHMENT,
        "wrap_algorithm": "AES-256-GCM",
        "wrap_nonce": b64url(bytes(12)),
        "wrapped_file_key": b64url(bytes(48)),
        "sender_signature_algorithm": "RSA-PKCS1-v1_5-SHA512",
        "sender_signature": b64url(signature),
    }
