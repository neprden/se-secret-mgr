#!/usr/bin/env python3
import base64
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import click
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NAME_RE = re.compile(r"^[A-Z0-9_]+$")

DEFAULT_SECRETS_DIR = Path.home() / ".secrets"
MASTER_IDENTITY = "master.key"   # age identity (SE/TouchID protected)
MASTER_AGE = "MASTER.age"        # age-encrypted base64(AES-256 key)
ENC_EXT = ".enc"

MAGIC = b"SEMG1"       # format marker
NONCE_LEN = 12         # AESGCM nonce length
DUMP_VERSION = 1

ENC_JSON_VERSION = 1   # .enc JSON container version


def die(msg: str) -> None:
    raise click.ClickException(msg)


def ensure_600(path: Path) -> None:
    try:
        path.chmod(0o600)
    except Exception:
        pass


def valid_name(name: str) -> bool:
    return bool(NAME_RE.fullmatch(name))


def list_enc_files(secrets_dir: Path) -> list[Path]:
    return sorted(p for p in secrets_dir.glob(f"*{ENC_EXT}") if p.is_file())


def run_checked(cmd: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        die(f"Command not found: {cmd[0]}")
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode("utf-8", "replace").strip()
        die(f"Command failed: {' '.join(cmd)}\n{err}")


def run_age_decrypt(identity_file: Path, master_age_file: Path) -> bytes:
    p = run_checked(["age", "-d", "-i", str(identity_file), str(master_age_file)])
    return p.stdout


def age_recipient_from_identity(identity_file: Path) -> str:
    """
    Extract recipient public key from master.key.

    Works for:
      - normal age identities
      - AGE-PLUGIN-* identities (Secure Enclave, etc.)

    It searches for:
      # public key: age1....
    """
    if not identity_file.exists():
        die(f"{identity_file} not found.")

    try:
        with identity_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("# public key:"):
                    parts = line.split()
                    if len(parts) >= 4 and parts[3].startswith("age1"):
                        return parts[3]
                    if parts and parts[-1].startswith("age1"):
                        return parts[-1]
    except Exception as e:
        die(f"Failed to read {identity_file}: {e}")

    die("Could not extract public key from master.key (no '# public key:' line found).")


def age_encrypt_to_recipient(recipient: str, plaintext: bytes) -> bytes:
    # Feed plaintext via stdin to avoid temp files
    try:
        p = subprocess.run(
            ["age", "-r", recipient],
            input=plaintext,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        die("age not found in PATH. Install age and retry.")
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode("utf-8", "replace").strip()
        die(f"age encrypt failed: {err}")
    return p.stdout


def load_aes_key(secrets_dir: Path) -> bytes:
    identity_file = secrets_dir / MASTER_IDENTITY
    master_age_file = secrets_dir / MASTER_AGE

    if not identity_file.exists():
        die(f"{MASTER_IDENTITY} not found. Expected at: {identity_file}")
    pub_key = age_recipient_from_identity(identity_file)
    if not master_age_file.exists():
        die(f"""
            {MASTER_AGE} not found. Expected at: {master_age_file}
            Use `age -r {pub_key} -o {master_age_file} <(openssl rand -base64 32)`
        """)

    plain = run_age_decrypt(identity_file, master_age_file)

    # MASTER.age plaintext expected: base64(32 bytes), possibly with whitespace/newline
    b64 = b"".join(plain.split())
    try:
        key = base64.b64decode(b64, validate=True)
    except Exception:
        die("MASTER.age plaintext is not valid base64. Expected base64(AES-256 key).")

    if len(key) != 32:
        die(f"Invalid AES key length: {len(key)} bytes. Expected 32 bytes for AES-256.")
    return key


def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return MAGIC + nonce + ct


def decrypt_bytes(key: bytes, blob: bytes) -> bytes:
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


def wrap_enc(cipher_blob: bytes, description: Optional[str]) -> bytes:
    """
    Always write NEW format: JSON container with cipher_b64 + description.

    - We NEVER create legacy raw-binary .enc anymore.
    - description is ALWAYS present (possibly empty string).
    """
    obj = {
        "v": ENC_JSON_VERSION,
        "cipher_b64": base64.b64encode(cipher_blob).decode("ascii"),
        "description": "" if description is None else str(description),
    }
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def unwrap_enc(data: bytes) -> Tuple[bytes, Optional[str], bool]:
    """
    Returns (cipher_blob, description, is_json_container).

    Supports:
      - new JSON container
      - old raw binary blob (backward compatibility)
    """
    # new: JSON
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

    # old: raw binary
    return data, None, False


@dataclass(frozen=True)
class Cfg:
    secrets_dir: Path

    @property
    def identity_file(self) -> Path:
        return self.secrets_dir / MASTER_IDENTITY

    @property
    def master_age_file(self) -> Path:
        return self.secrets_dir / MASTER_AGE


def ensure_setup(cfg: Cfg) -> None:
    if not cfg.secrets_dir.exists():
        die(f"""
            Secrets dir not found: {cfg.secrets_dir}
            Use `mkdir -p {cfg.secrets_dir}`
        """)
    if not cfg.identity_file.exists():
        die(f"""
            {MASTER_IDENTITY} not found. Expected at: {cfg.identity_file}
            Use `age-plugin-se keygen -o {cfg.secrets_dir}/{MASTER_IDENTITY}`
        """)
    pub_key = age_recipient_from_identity(cfg.identity_file)
    if not cfg.master_age_file.exists():
        die(f"""
            {MASTER_AGE} not found. Expected at: {cfg.master_age_file}
            Use `age -r {pub_key} -o {cfg.master_age_file} <(openssl rand -base64 32)`
        """)


def secret_path(cfg: Cfg, name: str) -> Path:
    return cfg.secrets_dir / f"{name}{ENC_EXT}"


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "--secrets-dir",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=DEFAULT_SECRETS_DIR,
    show_default=True,
    help="Directory containing master.key, MASTER.age and *.enc secrets.",
)
@click.pass_context
def cli(ctx: click.Context, secrets_dir: Path) -> None:
    """se-mgr (AES-256) — secrets manager with MASTER.age (age-wrapped AES key) + *.enc (AES-GCM)."""
    ctx.obj = Cfg(secrets_dir=secrets_dir)


@cli.command("set")
@click.argument("name", type=str)
@click.option(
    "--desc", "-d",
    default=None,
    help="Optional description metadata stored in .enc JSON. "
         "If omitted and metadata is preserved, keeps old description."
)
@click.option(
    "--preserve-meta/--no-preserve-meta",
    default=None,
    help="When overwriting an existing secret, preserve existing metadata (description). "
         "If not provided, you will be asked (only if there is something to preserve)."
)
@click.pass_obj
def cmd_set(cfg: Cfg, name: str, desc: Optional[str], preserve_meta: Optional[bool]) -> None:
    """Store secret NAME into NAME.enc (AES-256-GCM)."""
    ensure_setup(cfg)

    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

    out = secret_path(cfg, name)

    existed = out.exists()
    old_desc: Optional[str] = None
    preserve = False

    if existed:
        # read existing metadata BEFORE overwrite (best-effort)
        try:
            _old_cipher, old_desc, _old_is_json = unwrap_enc(out.read_bytes())
        except click.ClickException:
            old_desc = None

        if not click.confirm(f"⚠️  {name} exists. Overwrite?", default=False):
            return

        if preserve_meta is None:
            # Ask ONLY if there is real metadata to preserve (non-empty string)
            if old_desc:
                preserve = click.confirm("Preserve existing metadata (description)?", default=True)
            else:
                preserve = False
        else:
            preserve = preserve_meta

    secret = click.prompt(f"Enter value for {name}", hide_input=True, confirmation_prompt=True)

    key = load_aes_key(cfg.secrets_dir)
    cipher_blob = encrypt_bytes(key, secret.encode("utf-8"))

    # - If preserving and user did NOT provide --desc => keep old_desc (may be "" or None)
    # - If user provided --desc => use it (can clear via --desc "")
    # - If not preserving and --desc omitted => empty string (new JSON always has description)
    if preserve and desc is None:
        final_desc = old_desc or ""
    else:
        final_desc = "" if desc is None else desc.rstrip("\n")

    cfg.secrets_dir.mkdir(parents=True, exist_ok=True)
    out.write_bytes(wrap_enc(cipher_blob, final_desc))
    ensure_600(out)

    if existed and preserve:
        click.echo(f"✅ Stored {name} (metadata preserved)")
    else:
        click.echo(f"✅ Stored {name}")


@cli.command("get")
@click.argument("name", type=str)
@click.pass_obj
def cmd_get(cfg: Cfg, name: str) -> None:
    """Print decrypted secret NAME to stdout."""
    ensure_setup(cfg)
    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

    p = secret_path(cfg, name)
    if not p.exists():
        die(f"Secret not found: {name}")

    key = load_aes_key(cfg.secrets_dir)
    cipher_blob, _desc, _is_json = unwrap_enc(p.read_bytes())
    plain = decrypt_bytes(key, cipher_blob).decode("utf-8")
    click.get_text_stream("stdout").write(plain)


@cli.command("list")
@click.option("--long", "-l", "long_", is_flag=True, help="Show descriptions in YAML format.")
@click.pass_obj
def cmd_list(cfg: Cfg, long_: bool) -> None:
    """List secret names from *.enc files."""
    ensure_setup(cfg)

    files = list_enc_files(cfg.secrets_dir)

    if not long_:
        for p in files:
            click.echo(p.name[:-len(ENC_EXT)])
        return

    # YAML output
    for p in files:
        name = p.name[:-len(ENC_EXT)]
        click.echo(f"- name: {name}")

        try:
            _cipher_blob, desc, _is_json = unwrap_enc(p.read_bytes())
        except click.ClickException:
            desc = None

        # New JSON always has description (possibly ""), old raw may have None.
        if desc is None:
            continue

        if desc == "":
            click.echo('  description: ""')
            continue

        lines = desc.splitlines()
        if len(lines) == 1:
            click.echo(f"  description: {json.dumps(desc)}")
        else:
            click.echo("  description: |")
            for line in lines:
                click.echo(f"    {line}")


@cli.command("export")
@click.pass_obj
def cmd_export(cfg: Cfg) -> None:
    """Print shell export lines for all *.enc secrets."""
    ensure_setup(cfg)

    files = list_enc_files(cfg.secrets_dir)
    if not files:
        return

    key = load_aes_key(cfg.secrets_dir)
    out = click.get_text_stream("stdout")
    err = click.get_text_stream("stderr")

    for p in files:
        name = p.name[:-len(ENC_EXT)]
        if not valid_name(name):
            continue
        cipher_blob, _desc, _is_json = unwrap_enc(p.read_bytes())
        plain = decrypt_bytes(key, cipher_blob).decode("utf-8")
        err.write(f"# exporting {name}\n")
        out.write(f"export {name}={shlex.quote(plain)}\n")


@cli.command("comment")
@click.argument("name", type=str)
@click.argument("description", required=False)
@click.option("--stdin", "from_stdin", is_flag=True, help="Read description from stdin (allows multiline).")
@click.option("--file", "desc_file", type=click.Path(dir_okay=False, path_type=Path), help="Read description from file.")
@click.pass_obj
def cmd_comment(cfg: Cfg, name: str, description: Optional[str], from_stdin: bool, desc_file: Optional[Path]) -> None:
    """
    Set/replace description metadata for NAME.enc.

    - If file is old raw format: convert to JSON container and add description.
    - If file is JSON container: update description only (cipher remains unchanged).

    Multiline descriptions:
      - comment NAME --stdin
      - comment NAME --file desc.txt
    """
    ensure_setup(cfg)
    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

    # Choose input source
    sources = sum([1 if description is not None else 0, 1 if from_stdin else 0, 1 if desc_file else 0])
    if sources != 1:
        die("Provide exactly one of: DESCRIPTION argument, --stdin, or --file.")

    if from_stdin:
        description_text = click.get_text_stream("stdin").read()
    elif desc_file is not None:
        try:
            description_text = desc_file.read_text(encoding="utf-8")
        except Exception as e:
            die(f"Failed to read --file {desc_file}: {e}")
    else:
        description_text = description or ""

    # Per your request: if blank => store empty string (not None)
    new_desc = description_text.rstrip("\n")

    p = secret_path(cfg, name)
    if not p.exists():
        die(f"Secret not found: {name}")

    data = p.read_bytes()
    cipher_blob, _old_desc, is_json = unwrap_enc(data)

    p.write_bytes(wrap_enc(cipher_blob, new_desc))
    ensure_600(p)

    if is_json:
        click.echo(f"✅ Updated description for {name}")
    else:
        click.echo(f"✅ Converted {name} to JSON container and set description")


@cli.command("rm")
@click.argument("name", type=str)
@click.pass_obj
def cmd_rm(cfg: Cfg, name: str) -> None:
    """Delete secret NAME.enc (with confirmation)."""
    ensure_setup(cfg)
    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

    p = secret_path(cfg, name)
    if not p.exists():
        die(f"Secret not found: {name}")

    if click.confirm(f"🗑️  Delete {p.name}?", default=False):
        p.unlink()
        click.echo(f"✅ Deleted {name}")


@cli.command("rotate")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.pass_obj
def cmd_rotate(cfg: Cfg, yes: bool) -> None:
    """
    Rotate AES master key: generate new 32-byte key, re-encrypt all *.enc,
    and rewrite MASTER.age wrapped to current master.key recipient.
    """
    ensure_setup(cfg)

    files = list_enc_files(cfg.secrets_dir)
    if not yes:
        click.echo(f"About to rotate master key and re-encrypt {len(files)} secrets.")
        if not click.confirm("Proceed?", default=False):
            return

    # Load old key to decrypt secrets
    old_key = load_aes_key(cfg.secrets_dir)

    # Decrypt all secrets first (so we don't partially rotate on failure)
    decrypted: dict[str, tuple[bytes, Optional[str]]] = {}
    for p in files:
        name = p.name[:-len(ENC_EXT)]
        if not valid_name(name):
            continue
        cipher_blob, desc, _is_json = unwrap_enc(p.read_bytes())
        decrypted[name] = (decrypt_bytes(old_key, cipher_blob), desc)

    # Create new AES key
    new_key = os.urandom(32)

    # Rewrap MASTER.age for this identity
    recipient = age_recipient_from_identity(cfg.identity_file)
    master_plain_b64 = base64.b64encode(new_key) + b"\n"
    master_age_bytes = age_encrypt_to_recipient(recipient, master_plain_b64)

    # Write MASTER.age first to temp then replace atomically
    tmp_master = cfg.master_age_file.with_suffix(".age.tmp")
    tmp_master.write_bytes(master_age_bytes)
    ensure_600(tmp_master)
    tmp_master.replace(cfg.master_age_file)
    ensure_600(cfg.master_age_file)

    # Re-encrypt secrets with new key (keep descriptions; old raw => empty string)
    for name, (plain, desc) in decrypted.items():
        out = secret_path(cfg, name)
        cipher_blob = encrypt_bytes(new_key, plain)
        out.write_bytes(wrap_enc(cipher_blob, desc if desc is not None else ""))
        ensure_600(out)

    click.echo(f"✅ Rotated master key and re-encrypted {len(decrypted)} secrets.")


@cli.command("dump")
@click.option("--pretty", is_flag=True, help="Pretty-print JSON.")
@click.pass_obj
def cmd_dump(cfg: Cfg, pretty: bool) -> None:
    """
    Portable dump as JSON to stdout.

    Includes:
      - master_key_b64: base64(raw 32-byte AES key)   <-- PORTABLE, BUT SENSITIVE
      - secrets_enc_b64: NAME -> base64(bytes of NAME.enc) (these bytes may themselves be JSON)
    Does NOT include master.key.
    """
    ensure_setup(cfg)

    # This requires Touch ID (age decrypt of MASTER.age)
    master_key = load_aes_key(cfg.secrets_dir)  # 32 bytes

    secrets: dict[str, str] = {}
    for p in list_enc_files(cfg.secrets_dir):
        name = p.name[:-len(ENC_EXT)]
        if not valid_name(name):
            continue
        secrets[name] = base64.b64encode(p.read_bytes()).decode("ascii")

    payload = {
        "version": DUMP_VERSION,
        "format": "se-mgr-dump",
        "portable": True,
        # WARNING: plaintext master key in dump (base64) — protect this file!
        "master_key_b64": base64.b64encode(master_key).decode("ascii"),
        "secrets_enc_b64": secrets,
    }

    if pretty:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        click.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))


@cli.command("dump-apply")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.pass_obj
def cmd_dump_apply(cfg: Cfg, yes: bool) -> None:
    """
    Apply PORTABLE JSON dump from stdin:
      - writes *.enc files as-is (they might be raw or JSON container)
      - recreates MASTER.age by encrypting base64(master_key) to local master.key recipient
    """
    cfg.secrets_dir.mkdir(parents=True, exist_ok=True)

    raw = click.get_text_stream("stdin").read()
    if not raw.strip():
        die("No input on stdin.")

    try:
        payload = json.loads(raw)
    except Exception as e:
        die(f"Invalid JSON: {e}")

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

    # Decode master key (raw 32 bytes)
    try:
        master_key = base64.b64decode(master_key_b64.encode("ascii"), validate=True)
    except Exception:
        die("master_key_b64 is not valid base64.")
    if len(master_key) != 32:
        die(f"Invalid master key length: {len(master_key)} bytes (expected 32).")

    if not yes:
        click.echo(f"Will write {len(secrets)} secrets into: {cfg.secrets_dir}")
        click.echo(f"And will recreate {MASTER_AGE} using local {MASTER_IDENTITY}.")
        if not click.confirm("Proceed?", default=False):
            return

    # 1) Write secrets (*.enc) as-is
    count = 0
    for name, b64data in secrets.items():
        if not isinstance(name, str) or not valid_name(name):
            continue
        if not isinstance(b64data, str):
            continue
        enc_bytes = base64.b64decode(b64data.encode("ascii"))
        p = secret_path(cfg, name)
        p.write_bytes(enc_bytes)
        ensure_600(p)
        count += 1

    # 2) Recreate MASTER.age for THIS machine's identity (master.key)
    if not cfg.identity_file.exists():
        die(f"{MASTER_IDENTITY} not found at {cfg.identity_file}. Cannot create {MASTER_AGE}.")

    recipient = age_recipient_from_identity(cfg.identity_file)
    master_plain_b64 = base64.b64encode(master_key) + b"\n"
    master_age_bytes = age_encrypt_to_recipient(recipient, master_plain_b64)

    cfg.master_age_file.write_bytes(master_age_bytes)
    ensure_600(cfg.master_age_file)

    click.echo(f"✅ Applied portable dump: wrote {count} secrets and recreated {MASTER_AGE}.")


@cli.command("master")
@click.pass_obj
def cmd_masters(cfg: Cfg):
    click.echo(f"""
1. To generate SE master:
 - Use age SE plugin to generate: age-plugin-se keygen -o {cfg.secrets_dir}/{MASTER_IDENTITY}

2. To create shared master key:
 - create {MASTER_AGE}: `age -r {age_recipient_from_identity(cfg.identity_file)} -o {cfg.secrets_dir}/{MASTER_AGE} <(openssl rand -base64 32)`

 Current shared master: {base64.b64encode(load_aes_key(cfg.secrets_dir)).decode()}

"""
    )


if __name__ == "__main__":
    cli()
