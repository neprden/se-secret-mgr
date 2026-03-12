import base64
import json
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import MAGIC, NONCE_LEN, ENC_JSON_VERSION
from .utils import die


class CryptoEngine:
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return MAGIC + nonce + ct

    @staticmethod
    def decrypt(key: bytes, blob: bytes) -> bytes:
        if len(blob) < len(MAGIC) + NONCE_LEN + 16:
            die("Encrypted file is too short / corrupted.")
        if not blob.startswith(MAGIC):
            die("Encrypted file has unknown format (bad magic).")

        nonce = blob[len(MAGIC): len(MAGIC) + NONCE_LEN]
        ct = blob[len(MAGIC) + NONCE_LEN:]
        aesgcm = AESGCM(key)

        try:
            return aesgcm.decrypt(nonce, ct, associated_data=None)
        except Exception:
            die("Decryption failed (wrong key? corrupted file?).")

    @staticmethod
    def wrap_enc(cipher_blob: bytes, description: Optional[str]) -> bytes:
        obj = {
            "v": ENC_JSON_VERSION,
            "cipher_b64": base64.b64encode(cipher_blob).decode("ascii"),
            "description": "" if description is None else str(description),
        }
        return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

    @staticmethod
    def unwrap_enc(data: bytes) -> Tuple[bytes, Optional[str], bool]:
        """
        Returns (cipher_blob, description, is_json_container).

        Supports:
          - new JSON container
          - old raw binary blob (backward compatibility)
        """
        if data[:1] == b"{":
            try:
                obj = json.loads(data.decode("utf-8"))
            except Exception as e:
                die(f"Invalid .enc JSON: {e}")

            if int(obj.get("v", -1)) != ENC_JSON_VERSION:
                die(f"Unsupported .enc JSON version: {obj.get('v')}")

            cipher_b64 = obj.get("cipher_b64")
            if not isinstance(cipher_b64, str) or not cipher_b64:
                die("Invalid .enc JSON: missing cipher_b64")

            try:
                cipher_blob = base64.b64decode(cipher_b64.encode("ascii"), validate=True)
            except Exception:
                die("Invalid .enc JSON: cipher_b64 is not valid base64")

            desc = obj.get("description", "")
            if desc is None:
                desc = ""
            if not isinstance(desc, str):
                desc = str(desc)

            return cipher_blob, desc, True

        return data, None, False
