import base64
import json
import os
from pathlib import Path
from typing import Optional

import click

from .constants import (
    MASTER_IDENTITY, MASTER_AGE, ENC_EXT, DUMP_VERSION,
    DEFAULT_SECRETS_DIR,
)
from .utils import die, ensure_600, valid_name, list_enc_files, run_checked
from .crypto import CryptoEngine
from .age import AgeBackend


class SecretStore:
    def __init__(self, secrets_dir: Path = DEFAULT_SECRETS_DIR):
        self.secrets_dir = Path(secrets_dir).expanduser()

    @property
    def identity_file(self) -> Path:
        return self.secrets_dir / MASTER_IDENTITY

    @property
    def master_age_file(self) -> Path:
        return self.secrets_dir / MASTER_AGE

    def ensure_setup(self) -> None:
        if not self.secrets_dir.exists():
            die(f"""
            Secrets dir not found: {self.secrets_dir}
            Use `mkdir -p {self.secrets_dir}`
        """)
        if not self.identity_file.exists():
            die(f"""
            {MASTER_IDENTITY} not found. Expected at: {self.identity_file}
            Use `age-plugin-se keygen -o {self.secrets_dir}/{MASTER_IDENTITY}`
        """)
        pub_key = AgeBackend.get_recipient(self.identity_file)
        if not self.master_age_file.exists():
            die(f"""
            {MASTER_AGE} not found. Expected at: {self.master_age_file}
            Use `age -r {pub_key} -o {self.master_age_file} <(openssl rand -base64 32)`
        """)

    def load_aes_key(self) -> bytes:
        if not self.identity_file.exists():
            die(f"{MASTER_IDENTITY} not found. Expected at: {self.identity_file}")
        pub_key = AgeBackend.get_recipient(self.identity_file)
        if not self.master_age_file.exists():
            die(f"""
            {MASTER_AGE} not found. Expected at: {self.master_age_file}
            Use `age -r {pub_key} -o {self.master_age_file} <(openssl rand -base64 32)`
        """)

        plain = AgeBackend.decrypt(self.identity_file, self.master_age_file)

        b64 = b"".join(plain.split())
        try:
            key = base64.b64decode(b64, validate=True)
        except Exception:
            die("MASTER.age plaintext is not valid base64. Expected base64(AES-256 key).")

        if len(key) != 32:
            die(f"Invalid AES key length: {len(key)} bytes. Expected 32 bytes for AES-256.")
        return key

    def secret_path(self, name: str) -> Path:
        return self.secrets_dir / f"{name}{ENC_EXT}"

    def get(self, name: str) -> bytes:
        p = self.secret_path(name)
        if not p.exists():
            die(f"Secret not found: {name}")

        key = self.load_aes_key()
        cipher_blob, _desc, _is_json = CryptoEngine.unwrap_enc(p.read_bytes())
        return CryptoEngine.decrypt(key, cipher_blob)

    def set(self, name: str, value: bytes, desc: Optional[str],
            preserve_meta: bool, old_desc: Optional[str]) -> str:
        key = self.load_aes_key()
        cipher_blob = CryptoEngine.encrypt(key, value)

        if preserve_meta and desc is None:
            final_desc = old_desc or ""
        else:
            final_desc = "" if desc is None else desc.rstrip("\n")

        self.secrets_dir.mkdir(parents=True, exist_ok=True)
        out = self.secret_path(name)
        out.write_bytes(CryptoEngine.wrap_enc(cipher_blob, final_desc))
        ensure_600(out)

        if preserve_meta:
            return f"Stored {name} (metadata preserved)"
        return f"Stored {name}"

    def delete(self, name: str) -> None:
        p = self.secret_path(name)
        if not p.exists():
            die(f"Secret not found: {name}")
        p.unlink()

    def rename(self, old: str, new: str, force: bool) -> None:
        src = self.secret_path(old)
        dst = self.secret_path(new)

        if not src.exists():
            die(f"Secret not found: {old}")

        if dst.exists() and not force:
            die(f"{new} already exists (use --force to overwrite)")

        src.replace(dst)
        ensure_600(dst)

    def list_secrets(self, long_: bool = False) -> list:
        files = list_enc_files(self.secrets_dir)

        if not long_:
            return [p.name[:-len(ENC_EXT)] for p in files]

        result = []
        for p in files:
            name = p.name[:-len(ENC_EXT)]
            entry = {"name": name}
            try:
                _cipher_blob, desc, _is_json = CryptoEngine.unwrap_enc(p.read_bytes())
            except click.ClickException:
                desc = None
            entry["description"] = desc
            result.append(entry)
        return result

    def export_all(self) -> list[tuple[str, str]]:
        files = list_enc_files(self.secrets_dir)
        if not files:
            return []

        key = self.load_aes_key()
        result = []
        for p in files:
            name = p.name[:-len(ENC_EXT)]
            if not valid_name(name):
                continue
            cipher_blob, _desc, _is_json = CryptoEngine.unwrap_enc(p.read_bytes())
            plain = CryptoEngine.decrypt(key, cipher_blob).decode("utf-8")
            result.append((name, plain))
        return result

    def set_comment(self, name: str, description: str) -> bool:
        p = self.secret_path(name)
        if not p.exists():
            die(f"Secret not found: {name}")

        data = p.read_bytes()
        cipher_blob, _old_desc, is_json = CryptoEngine.unwrap_enc(data)

        p.write_bytes(CryptoEngine.wrap_enc(cipher_blob, description))
        ensure_600(p)
        return is_json

    def rotate(self) -> int:
        files = list_enc_files(self.secrets_dir)
        old_key = self.load_aes_key()

        decrypted: dict[str, tuple[bytes, Optional[str]]] = {}
        for p in files:
            name = p.name[:-len(ENC_EXT)]
            if not valid_name(name):
                continue
            cipher_blob, desc, _is_json = CryptoEngine.unwrap_enc(p.read_bytes())
            decrypted[name] = (CryptoEngine.decrypt(old_key, cipher_blob), desc)

        new_key = os.urandom(32)

        recipient = AgeBackend.get_recipient(self.identity_file)
        master_plain_b64 = base64.b64encode(new_key) + b"\n"
        master_age_bytes = AgeBackend.encrypt_to_recipient(recipient, master_plain_b64)

        tmp_master = self.master_age_file.with_suffix(".age.tmp")
        tmp_master.write_bytes(master_age_bytes)
        ensure_600(tmp_master)
        tmp_master.replace(self.master_age_file)
        ensure_600(self.master_age_file)

        for name, (plain, desc) in decrypted.items():
            out = self.secret_path(name)
            cipher_blob = CryptoEngine.encrypt(new_key, plain)
            out.write_bytes(CryptoEngine.wrap_enc(cipher_blob, desc if desc is not None else ""))
            ensure_600(out)

        return len(decrypted)

    def dump(self) -> dict:
        master_key = self.load_aes_key()

        secrets: dict[str, str] = {}
        for p in list_enc_files(self.secrets_dir):
            name = p.name[:-len(ENC_EXT)]
            if not valid_name(name):
                continue
            secrets[name] = base64.b64encode(p.read_bytes()).decode("ascii")

        return {
            "version": DUMP_VERSION,
            "format": "se-mgr-dump",
            "portable": True,
            "master_key_b64": base64.b64encode(master_key).decode("ascii"),
            "secrets_enc_b64": secrets,
        }

    def apply_dump(self, payload: dict) -> int:
        self.secrets_dir.mkdir(parents=True, exist_ok=True)

        if payload.get("format") != "se-mgr-dump":
            die("Not a se-mgr dump (format mismatch).")
        if int(payload.get("version", -1)) != DUMP_VERSION:
            die(f"Unsupported dump version: {payload.get('version')}")
        if payload.get("portable") is not True:
            die("This dump is not marked as portable=True.")

        master_key_b64 = payload.get("master_key_b64")
        secrets = payload.get("secrets_enc_b64", {})

        if not isinstance(master_key_b64, str) or not master_key_b64:
            die("Dump missing master_key_b64.")
        if not isinstance(secrets, dict):
            die("Dump secrets_enc_b64 must be an object/dict.")

        try:
            master_key = base64.b64decode(master_key_b64.encode("ascii"), validate=True)
        except Exception:
            die("master_key_b64 is not valid base64.")
        if len(master_key) != 32:
            die(f"Invalid master key length: {len(master_key)} bytes (expected 32).")

        count = 0
        for name, b64data in secrets.items():
            if not isinstance(name, str) or not valid_name(name):
                continue
            if not isinstance(b64data, str):
                continue
            enc_bytes = base64.b64decode(b64data.encode("ascii"))
            p = self.secret_path(name)
            p.write_bytes(enc_bytes)
            ensure_600(p)
            count += 1

        if not self.identity_file.exists():
            die(f"{MASTER_IDENTITY} not found at {self.identity_file}. Cannot create {MASTER_AGE}.")

        recipient = AgeBackend.get_recipient(self.identity_file)
        master_plain_b64 = base64.b64encode(master_key) + b"\n"
        master_age_bytes = AgeBackend.encrypt_to_recipient(recipient, master_plain_b64)

        self.master_age_file.write_bytes(master_age_bytes)
        ensure_600(self.master_age_file)

        return count

    def master_info(self) -> dict:
        identity_exists = self.identity_file.exists()
        master_exists = self.master_age_file.exists()

        recipient_hint = "<recipient unavailable: generate master.key first>"
        if identity_exists:
            try:
                recipient_hint = AgeBackend.get_recipient(self.identity_file)
            except click.ClickException:
                recipient_hint = "<recipient unavailable: failed to parse master.key>"

        current_master = None
        master_error = None
        if master_exists:
            try:
                current_master = base64.b64encode(self.load_aes_key()).decode("ascii")
            except click.ClickException as e:
                master_error = e.format_message()

        return {
            "identity_file": self.identity_file,
            "master_age_file": self.master_age_file,
            "identity_exists": identity_exists,
            "master_exists": master_exists,
            "recipient_hint": recipient_hint,
            "current_master": current_master,
            "master_error": master_error,
        }

    @staticmethod
    def init_temp(secrets_dir: Path) -> "SecretStore":
        secrets_dir.mkdir(parents=True, exist_ok=True)

        identity_file = secrets_dir / MASTER_IDENTITY
        master_age_file = secrets_dir / MASTER_AGE

        if not identity_file.exists():
            run_checked(["age-keygen", "-o", str(identity_file)])
            ensure_600(identity_file)

        recipient = AgeBackend.get_recipient(identity_file)

        aes_key = os.urandom(32)
        master_plain_b64 = base64.b64encode(aes_key) + b"\n"
        master_age_bytes = AgeBackend.encrypt_to_recipient(recipient, master_plain_b64)

        master_age_file.write_bytes(master_age_bytes)
        ensure_600(master_age_file)

        return SecretStore(secrets_dir)
