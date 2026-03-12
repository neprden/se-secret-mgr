import subprocess
from pathlib import Path

import click

from .constants import NAME_RE, ENC_EXT


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
