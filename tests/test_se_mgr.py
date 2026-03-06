from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess

import click
from click.testing import CliRunner
import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "se-mgr.py"
spec = importlib.util.spec_from_file_location("se_mgr", MODULE_PATH)
assert spec is not None and spec.loader is not None
se_mgr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se_mgr)


def test_valid_name_rules() -> None:
    assert se_mgr.valid_name("API_TOKEN") is True
    assert se_mgr.valid_name("A") is False
    assert se_mgr.valid_name("api_token") is False


def test_wrap_unwrap_roundtrip_with_description() -> None:
    cipher = b"cipher-bytes"
    wrapped = se_mgr.wrap_enc(cipher, "line1\\nline2")

    unwrapped_cipher, description, is_json = se_mgr.unwrap_enc(wrapped)

    assert is_json is True
    assert unwrapped_cipher == cipher
    assert description == "line1\\nline2"


def test_wrap_unwrap_roundtrip_without_description() -> None:
    cipher = b"cipher-bytes"
    wrapped = se_mgr.wrap_enc(cipher, None)

    unwrapped_cipher, description, is_json = se_mgr.unwrap_enc(wrapped)

    assert is_json is True
    assert unwrapped_cipher == cipher
    assert description == ""


def test_unwrap_legacy_raw_format() -> None:
    raw = b"legacy-blob"
    cipher, description, is_json = se_mgr.unwrap_enc(raw)

    assert cipher == raw
    assert description is None
    assert is_json is False


def test_encrypt_decrypt_roundtrip() -> None:
    key = bytes(range(32))
    plain = b"line1\\nline2\\n"

    blob = se_mgr.encrypt_bytes(key, plain)

    assert se_mgr.decrypt_bytes(key, blob) == plain


def test_decrypt_rejects_bad_magic() -> None:
    key = bytes(range(32))
    with pytest.raises(click.ClickException, match="bad magic"):
        se_mgr.decrypt_bytes(key, b"BAD!!" + b"x" * 64)


def test_set_from_file_multiline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    secret_path = tmp_path / "secret.txt"
    secret_bytes = b"line1\nline2\nline3"
    secret_path.write_bytes(secret_bytes)

    monkeypatch.setattr(se_mgr, "ensure_setup", lambda _cfg: None)
    monkeypatch.setattr(se_mgr, "load_aes_key", lambda _secrets_dir: bytes([0x11]) * 32)

    runner = CliRunner()
    result = runner.invoke(
        se_mgr.cli,
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

    cipher_blob, description, is_json = se_mgr.unwrap_enc(enc_file.read_bytes())
    plain = se_mgr.decrypt_bytes(bytes([0x11]) * 32, cipher_blob)

    assert is_json is True
    assert description == ""
    assert plain == secret_bytes


def test_set_from_file_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()

    monkeypatch.setattr(se_mgr, "ensure_setup", lambda _cfg: None)

    runner = CliRunner()
    result = runner.invoke(
        se_mgr.cli,
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

    monkeypatch.setattr(se_mgr, "ensure_setup", lambda _cfg: None)

    original_cipher = b"cipher-blob"
    enc_file = secrets_dir / "TEST_SECRET.enc"
    enc_file.write_bytes(se_mgr.wrap_enc(original_cipher, "old"))

    desc_file = tmp_path / "desc.txt"
    desc_file.write_text("first line\nsecond line\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        se_mgr.cli,
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
    updated_cipher, updated_description, is_json = se_mgr.unwrap_enc(enc_file.read_bytes())

    assert is_json is True
    assert updated_cipher == original_cipher
    assert updated_description == "first line\nsecond line"


def test_master_command_on_empty_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(se_mgr.cli, ["--secrets-dir", str(tmp_path), "master"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "1. To generate SE master:" in result.output
    assert "2. To create shared master key:" in result.output
    assert "completed: False" in result.output


def test_dump_apply_rejects_invalid_json(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        se_mgr.cli,
        ["--secrets-dir", str(tmp_path), "dump-apply", "--yes"],
        input="not-json",
    )

    assert result.exit_code != 0
    assert "Invalid JSON" in result.output


def test_run_checked_command_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_not_found(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(se_mgr.subprocess, "run", _raise_not_found)

    with pytest.raises(click.ClickException, match="Command not found: age"):
        se_mgr.run_checked(["age", "--version"])


def test_run_checked_called_process_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_cpe(*_args, **_kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=["age", "-d"], stderr=b"boom")

    monkeypatch.setattr(se_mgr.subprocess, "run", _raise_cpe)

    with pytest.raises(click.ClickException, match="Command failed: age -d"):
        se_mgr.run_checked(["age", "-d"])


def test_unwrap_enc_invalid_json_raises() -> None:
    with pytest.raises(click.ClickException, match="Invalid .enc JSON"):
        se_mgr.unwrap_enc(b"{invalid-json")


def test_unwrap_enc_invalid_version_raises() -> None:
    bad = b'{"v":999,"cipher_b64":"AA==","description":""}'
    with pytest.raises(click.ClickException, match="Unsupported .enc JSON version"):
        se_mgr.unwrap_enc(bad)


def test_unwrap_enc_missing_cipher_b64_raises() -> None:
    bad = b'{"v":1,"description":""}'
    with pytest.raises(click.ClickException, match="missing cipher_b64"):
        se_mgr.unwrap_enc(bad)


def test_unwrap_enc_invalid_cipher_b64_raises() -> None:
    bad = b'{"v":1,"cipher_b64":"***","description":""}'
    with pytest.raises(click.ClickException, match="cipher_b64 is not valid base64"):
        se_mgr.unwrap_enc(bad)


def test_load_aes_key_missing_identity(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException, match="master.key not found"):
        se_mgr.load_aes_key(tmp_path)
