from __future__ import annotations

from pathlib import Path
import subprocess

import click
from click.testing import CliRunner
import pytest

from se_secret_mgr.utils import valid_name, run_checked
from se_secret_mgr.crypto import CryptoEngine
from se_secret_mgr.store import SecretStore
from se_mgr_cli import cli


def test_valid_name_rules() -> None:
    assert valid_name("API_TOKEN") is True
    assert valid_name("A") is False
    assert valid_name("api_token") is False


def test_wrap_unwrap_roundtrip_with_description() -> None:
    cipher = b"cipher-bytes"
    wrapped = CryptoEngine.wrap_enc(cipher, "line1\\nline2")

    unwrapped_cipher, description, is_json = CryptoEngine.unwrap_enc(wrapped)

    assert is_json is True
    assert unwrapped_cipher == cipher
    assert description == "line1\\nline2"


def test_wrap_unwrap_roundtrip_without_description() -> None:
    cipher = b"cipher-bytes"
    wrapped = CryptoEngine.wrap_enc(cipher, None)

    unwrapped_cipher, description, is_json = CryptoEngine.unwrap_enc(wrapped)

    assert is_json is True
    assert unwrapped_cipher == cipher
    assert description == ""


def test_unwrap_legacy_raw_format() -> None:
    raw = b"legacy-blob"
    cipher, description, is_json = CryptoEngine.unwrap_enc(raw)

    assert cipher == raw
    assert description is None
    assert is_json is False


def test_encrypt_decrypt_roundtrip() -> None:
    key = bytes(range(32))
    plain = b"line1\\nline2\\n"

    blob = CryptoEngine.encrypt(key, plain)

    assert CryptoEngine.decrypt(key, blob) == plain


def test_decrypt_rejects_bad_magic() -> None:
    key = bytes(range(32))
    with pytest.raises(click.ClickException, match="bad magic"):
        CryptoEngine.decrypt(key, b"BAD!!" + b"x" * 64)


def test_set_from_file_multiline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    secret_path = tmp_path / "secret.txt"
    secret_bytes = b"line1\nline2\nline3"
    secret_path.write_bytes(secret_bytes)

    monkeypatch.setattr("se_secret_mgr.store.AgeBackend.get_recipient", lambda _f: "age1fake")
    monkeypatch.setattr("se_secret_mgr.store.AgeBackend.decrypt", lambda _i, _m: b"")
    monkeypatch.setattr(SecretStore, "ensure_setup", lambda _self: None)
    monkeypatch.setattr(SecretStore, "load_aes_key", lambda _self: bytes([0x11]) * 32)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--secrets-dir",
            str(secrets_dir),
            "set",
            "TEST_SECRET",
            "--from-file",
            str(secret_path),
            "--no-preserve-meta",
        ],
        catch_exceptions=False,
    )

    assert result.exit_code == 0

    enc_file = secrets_dir / "TEST_SECRET.enc"
    assert enc_file.exists()

    cipher_blob, description, is_json = CryptoEngine.unwrap_enc(enc_file.read_bytes())
    plain = CryptoEngine.decrypt(bytes([0x11]) * 32, cipher_blob)

    assert is_json is True
    assert description == ""
    assert plain == secret_bytes


def test_set_from_file_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()

    monkeypatch.setattr(SecretStore, "ensure_setup", lambda _self: None)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--secrets-dir",
            str(secrets_dir),
            "set",
            "TEST_SECRET",
            "--from-file",
            str(tmp_path / "missing.txt"),
        ],
    )

    assert result.exit_code != 0
    assert "File not found:" in result.output


def test_comment_from_file_updates_description(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()

    monkeypatch.setattr(SecretStore, "ensure_setup", lambda _self: None)

    original_cipher = b"cipher-blob"
    enc_file = secrets_dir / "TEST_SECRET.enc"
    enc_file.write_bytes(CryptoEngine.wrap_enc(original_cipher, "old"))

    desc_file = tmp_path / "desc.txt"
    desc_file.write_text("first line\nsecond line\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--secrets-dir",
            str(secrets_dir),
            "comment",
            "TEST_SECRET",
            "--file",
            str(desc_file),
        ],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    updated_cipher, updated_description, is_json = CryptoEngine.unwrap_enc(enc_file.read_bytes())

    assert is_json is True
    assert updated_cipher == original_cipher
    assert updated_description == "first line\nsecond line"


def test_master_command_on_empty_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--secrets-dir", str(tmp_path), "master"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "1. To generate SE master:" in result.output
    assert "2. To create shared master key:" in result.output
    assert "completed: False" in result.output


def test_dump_apply_rejects_invalid_json(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--secrets-dir", str(tmp_path), "dump-apply", "--yes"],
        input="not-json",
    )

    assert result.exit_code != 0
    assert "Invalid JSON" in result.output


def test_run_checked_command_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_not_found(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("se_secret_mgr.utils.subprocess.run", _raise_not_found)

    with pytest.raises(click.ClickException, match="Command not found: age"):
        run_checked(["age", "--version"])


def test_run_checked_called_process_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_cpe(*_args, **_kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=["age", "-d"], stderr=b"boom")

    monkeypatch.setattr("se_secret_mgr.utils.subprocess.run", _raise_cpe)

    with pytest.raises(click.ClickException, match="Command failed: age -d"):
        run_checked(["age", "-d"])


def test_unwrap_enc_invalid_json_raises() -> None:
    with pytest.raises(click.ClickException, match="Invalid .enc JSON"):
        CryptoEngine.unwrap_enc(b"{invalid-json")


def test_unwrap_enc_invalid_version_raises() -> None:
    bad = b'{"v":999,"cipher_b64":"AA==","description":""}'
    with pytest.raises(click.ClickException, match="Unsupported .enc JSON version"):
        CryptoEngine.unwrap_enc(bad)


def test_unwrap_enc_missing_cipher_b64_raises() -> None:
    bad = b'{"v":1,"description":""}'
    with pytest.raises(click.ClickException, match="missing cipher_b64"):
        CryptoEngine.unwrap_enc(bad)


def test_unwrap_enc_invalid_cipher_b64_raises() -> None:
    bad = b'{"v":1,"cipher_b64":"***","description":""}'
    with pytest.raises(click.ClickException, match="cipher_b64 is not valid base64"):
        CryptoEngine.unwrap_enc(bad)


def test_load_aes_key_missing_identity(tmp_path: Path) -> None:
    store = SecretStore(tmp_path)
    with pytest.raises(click.ClickException, match="master.key not found"):
        store.load_aes_key()
