#!/usr/bin/env python3
import json
import secrets
import shlex
import tempfile
from pathlib import Path
from typing import Optional

import click
from click.testing import CliRunner

from se_secret_mgr import (
    DEFAULT_SECRETS_DIR, MASTER_IDENTITY, MASTER_AGE,
    valid_name, die,
)
from se_secret_mgr.crypto import CryptoEngine
from se_secret_mgr.store import SecretStore


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "--secrets-dir", '-d',
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=DEFAULT_SECRETS_DIR,
    show_default=True,
    help="Directory containing master.key, MASTER.age and *.enc secrets.",
)
@click.pass_context
def cli(ctx: click.Context, secrets_dir: Path) -> None:
    """se-mgr (AES-256) — secrets manager with MASTER.age (age-wrapped AES key) + *.enc (AES-GCM)."""
    ctx.obj = SecretStore(secrets_dir=secrets_dir)


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
@click.option(
    "--from-file", "-f",
    "from_file",
    type=str,
    default=None,
    help="Read secret value from file path (use '-' for stdin). Supports multiline secrets."
)
@click.pass_obj
def cmd_set(
    store: SecretStore,
    name: str,
    desc: Optional[str],
    preserve_meta: Optional[bool],
    from_file: Optional[str],
) -> None:
    """Store secret NAME into NAME.enc (AES-256-GCM)."""
    store.ensure_setup()

    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

    out = store.secret_path(name)

    existed = out.exists()
    old_desc: Optional[str] = None
    preserve = False

    if existed:
        try:
            _old_cipher, old_desc, _old_is_json = CryptoEngine.unwrap_enc(out.read_bytes())
        except click.ClickException:
            old_desc = None

        if not click.confirm(f"\u26a0\ufe0f  {name} exists. Overwrite?", default=False):
            return

        if preserve_meta is None:
            if old_desc:
                preserve = click.confirm("Preserve existing metadata (description)?", default=True)
            else:
                preserve = False
        else:
            preserve = preserve_meta

    if from_file is not None:
        if from_file == "-":
            secret = click.get_binary_stream("stdin").read()
        else:
            src = Path(from_file).expanduser()
            if not src.exists():
                raise click.ClickException(f"File not found: {src}")
            if not src.is_file():
                raise click.ClickException(f"Not a file: {src}")
            secret = src.read_bytes()
    else:
        typed_secret = click.prompt(f"Enter value for {name}", hide_input=True, confirmation_prompt=True)
        secret = typed_secret.encode("utf-8")

    msg = store.set(name, secret, desc, preserve, old_desc)
    click.echo(f"\u2705 {msg}")


@cli.command("get")
@click.argument("name", type=str)
@click.pass_obj
def cmd_get(store: SecretStore, name: str) -> None:
    """Print decrypted secret NAME to stdout."""
    store.ensure_setup()
    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

    plain = store.get(name).decode("utf-8")
    click.get_text_stream("stdout").write(plain)


@cli.command("list")
@click.option("--long", "-l", "long_", is_flag=True, help="Show descriptions in YAML format.")
@click.pass_obj
def cmd_list(store: SecretStore, long_: bool) -> None:
    """List secret names from *.enc files."""
    store.ensure_setup()

    items = store.list_secrets(long_=long_)

    if not long_:
        for name in items:
            click.echo(name)
        return

    for entry in items:
        name = entry["name"]
        desc = entry["description"]
        click.echo(f"- name: {name}")

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
def cmd_export(store: SecretStore) -> None:
    """Print shell export lines for all *.enc secrets."""
    store.ensure_setup()

    pairs = store.export_all()
    out = click.get_text_stream("stdout")
    err = click.get_text_stream("stderr")

    for name, plain in pairs:
        err.write(f"# exporting {name}\n")
        out.write(f"export {name}={shlex.quote(plain)}\n")


@cli.command("comment")
@click.argument("name", type=str)
@click.argument("description", required=False)
@click.option("--stdin", "from_stdin", is_flag=True, help="Read description from stdin (allows multiline).")
@click.option("--file", "desc_file", type=click.Path(dir_okay=False, path_type=Path), help="Read description from file.")
@click.pass_obj
def cmd_comment(store: SecretStore, name: str, description: Optional[str], from_stdin: bool, desc_file: Optional[Path]) -> None:
    """
    Set/replace description metadata for NAME.enc.

    - If file is old raw format: convert to JSON container and add description.
    - If file is JSON container: update description only (cipher remains unchanged).

    Multiline descriptions:
      - comment NAME --stdin
      - comment NAME --file desc.txt
    """
    store.ensure_setup()
    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

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

    new_desc = description_text.rstrip("\n")

    was_json = store.set_comment(name, new_desc)

    if was_json:
        click.echo(f"\u2705 Updated description for {name}")
    else:
        click.echo(f"\u2705 Converted {name} to JSON container and set description")


@cli.command("rm")
@click.argument("name", type=str)
@click.pass_obj
def cmd_rm(store: SecretStore, name: str) -> None:
    """Delete secret NAME.enc (with confirmation)."""
    store.ensure_setup()
    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

    p = store.secret_path(name)
    if not p.exists():
        die(f"Secret not found: {name}")

    if click.confirm(f"\U0001f5d1\ufe0f  Delete {p.name}?", default=False):
        store.delete(name)
        click.echo(f"\u2705 Deleted {name}")


@cli.command("rotate")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.pass_obj
def cmd_rotate(store: SecretStore, yes: bool) -> None:
    """
    Rotate AES master key: generate new 32-byte key, re-encrypt all *.enc,
    and rewrite MASTER.age wrapped to current master.key recipient.
    """
    store.ensure_setup()

    from se_secret_mgr.utils import list_enc_files
    from se_secret_mgr.constants import ENC_EXT
    files = list_enc_files(store.secrets_dir)
    if not yes:
        click.echo(f"About to rotate master key and re-encrypt {len(files)} secrets.")
        if not click.confirm("Proceed?", default=False):
            return

    count = store.rotate()
    click.echo(f"\u2705 Rotated master key and re-encrypted {count} secrets.")


@cli.command("dump")
@click.option("--pretty", is_flag=True, help="Pretty-print JSON.")
@click.pass_obj
def cmd_dump(store: SecretStore, pretty: bool) -> None:
    """
    Portable dump as JSON to stdout.

    Includes:
      - master_key_b64: base64(raw 32-byte AES key)   <-- PORTABLE, BUT SENSITIVE
      - secrets_enc_b64: NAME -> base64(bytes of NAME.enc) (these bytes may themselves be JSON)
    Does NOT include master.key.
    """
    store.ensure_setup()

    payload = store.dump()

    if pretty:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        click.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))


@cli.command("dump-apply")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.pass_obj
def cmd_dump_apply(store: SecretStore, yes: bool) -> None:
    """
    Apply PORTABLE JSON dump from stdin:
      - writes *.enc files as-is (they might be raw or JSON container)
      - recreates MASTER.age by encrypting base64(master_key) to local master.key recipient
    """
    raw = click.get_text_stream("stdin").read()
    if not raw.strip():
        die("No input on stdin.")

    try:
        payload = json.loads(raw)
    except Exception as e:
        die(f"Invalid JSON: {e}")

    if not yes:
        secrets = payload.get("secrets_enc_b64", {})
        click.echo(f"Will write {len(secrets)} secrets into: {store.secrets_dir}")
        click.echo(f"And will recreate {MASTER_AGE} using local {MASTER_IDENTITY}.")
        if not click.confirm("Proceed?", default=False):
            return

    count = store.apply_dump(payload)
    click.echo(f"\u2705 Applied portable dump: wrote {count} secrets and recreated {MASTER_AGE}.")


@cli.command("master")
@click.pass_obj
def cmd_masters(store: SecretStore) -> None:
    info = store.master_info()

    click.echo("1. To generate SE master:")
    click.echo(f" - Use age SE plugin to generate: age-plugin-se keygen -o {info['identity_file']}")
    click.echo(f"   completed: {info['identity_exists']}")
    click.echo("")

    click.echo("2. To create shared master key:")
    click.echo(f" - create {MASTER_AGE}: `age -r {info['recipient_hint']} -o {info['master_age_file']} <(openssl rand -base64 32)`")
    click.echo(f"   completed: {info['master_exists']}")

    if info["master_exists"]:
        if info["current_master"]:
            click.echo(f"   Current shared master: {info['current_master']}")
        elif info["master_error"]:
            click.echo(f"   Could not read current shared master: {info['master_error']}")


@cli.command("pbcopy")
@click.argument("name", type=str)
@click.option(
    "--clear-after",
    type=int,
    default=0,
    help="Clear clipboard after N seconds.",
)
@click.pass_obj
def cmd_pbcopy(store: SecretStore, name: str, clear_after: int) -> None:
    """
    Decrypt secret NAME and copy it to system clipboard.
    Does NOT print the secret.
    """
    store.ensure_setup()

    if not valid_name(name):
        die("Invalid name (use A-Z0-9_)")

    secret = store.get(name).decode("utf-8")

    try:
        import pyperclip
    except ImportError:
        die("pyperclip not installed. Run: pip install pyperclip")

    try:
        pyperclip.copy(secret)
    except Exception as e:
        die(f"Failed to copy to clipboard: {e}")

    if clear_after > 0:
        import threading
        import time

        def clear():
            time.sleep(clear_after)
            try:
                if pyperclip.paste() == secret:
                    pyperclip.copy("")
            except Exception:
                pass

        threading.Thread(target=clear, daemon=True).start()


@cli.command("mv")
@click.argument("old", type=str)
@click.argument("new", type=str)
@click.option("--force", "-f", is_flag=True, help="Overwrite destination if it exists.")
@click.pass_obj
def cmd_mv(store: SecretStore, old: str, new: str, force: bool) -> None:
    """Rename secret OLD -> NEW (moves OLD.enc to NEW.enc)."""
    store.ensure_setup()

    if not valid_name(old) or not valid_name(new):
        die("Invalid name (use A-Z0-9_)")

    if old == new:
        click.echo("Nothing to do (same name).")
        return

    dst = store.secret_path(new)
    if dst.exists():
        if not force:
            if not click.confirm(f"\u26a0\ufe0f  {new} exists. Overwrite?", default=False):
                return

    store.rename(old, new, force=True)
    click.echo(f"\u2705 Renamed {old} -> {new}")


@cli.command("test")
@click.option("--keep-temp", is_flag=True, help="Keep temp test directories and print their paths.")
@click.option("--verbose", "-v", is_flag=True, help="Print per-step details (no secret contents).")
@click.pass_obj
def cmd_test(store: SecretStore, keep_temp: bool, verbose: bool) -> None:
    """
    Self-test: runs commands against a BRAND NEW temp store.
    Does not touch your real secrets.
    """
    runner = CliRunner()

    t1_td = tempfile.TemporaryDirectory(prefix="se-mgr-test-")
    t2_td = tempfile.TemporaryDirectory(prefix="se-mgr-test-apply-")
    t1 = Path(t1_td.name)
    t2 = Path(t2_td.name)

    def invoke_in_dir(secrets_dir: Path, args: list[str], input_text: str = ""):
        full_args = ["--secrets-dir", str(secrets_dir)] + args
        return runner.invoke(cli, full_args, input=input_text, catch_exceptions=False)

    try:
        SecretStore.init_temp(t1)
        SecretStore.init_temp(t2)

        suffix = secrets.token_hex(4).upper()
        a = f"TEST_A_{suffix}"
        b = f"TEST_B_{suffix}"
        val = f"v_{secrets.token_hex(16)}"

        steps: list[tuple[str, callable]] = []

        def step_list_empty_or_ok():
            r = invoke_in_dir(t1, ["list"])
            if r.exit_code != 0:
                raise RuntimeError(r.output)

        def step_set_get():
            r_set = invoke_in_dir(t1, ["set", a, "--desc", "self-test", "--no-preserve-meta"],
                                  input_text=f"{val}\n{val}\n")
            if r_set.exit_code != 0:
                raise RuntimeError(f"set failed:\n{r_set.output}")

            r_get = invoke_in_dir(t1, ["get", a])
            if r_get.exit_code != 0:
                raise RuntimeError(f"get failed:\n{r_get.output}")
            if r_get.output != val:
                raise RuntimeError("get output mismatch (expected exact secret value).")

        def step_set_from_file_multiline():
            c = f"TEST_C_{suffix}"
            multiline = f"{val}\nline2\nline3"
            secret_file = t1 / "multiline-secret.txt"
            secret_file.write_text(multiline, encoding="utf-8")

            r_set = invoke_in_dir(
                t1,
                ["set", c, "--from-file", str(secret_file), "--desc", "multiline", "--no-preserve-meta"],
            )
            if r_set.exit_code != 0:
                raise RuntimeError(f"set --from-file failed:\n{r_set.output}")

            r_get = invoke_in_dir(t1, ["get", c])
            if r_get.exit_code != 0:
                raise RuntimeError(f"get(multiline) failed:\n{r_get.output}")
            if r_get.output != multiline:
                raise RuntimeError("multiline secret mismatch after set --from-file.")

        def step_mv_and_verify():
            r_mv = invoke_in_dir(t1, ["mv", a, b], input_text="y\n")
            if r_mv.exit_code != 0:
                raise RuntimeError(f"mv failed:\n{r_mv.output}")

            r_get_old = invoke_in_dir(t1, ["get", a])
            if r_get_old.exit_code == 0:
                raise RuntimeError("get(old) succeeded after mv (expected failure).")

            r_get_new = invoke_in_dir(t1, ["get", b])
            if r_get_new.exit_code != 0:
                raise RuntimeError(f"get(new) failed:\n{r_get_new.output}")
            if r_get_new.output != val:
                raise RuntimeError("get(new) output mismatch after mv.")

        def step_comment_and_export():
            r_cmt = invoke_in_dir(t1, ["comment", b, "--stdin"], input_text="line1\nline2\n")
            if r_cmt.exit_code != 0:
                raise RuntimeError(f"comment failed:\n{r_cmt.output}")

            r_exp = invoke_in_dir(t1, ["export"])
            if r_exp.exit_code != 0:
                raise RuntimeError(f"export failed:\n{r_exp.output}")
            if f"export {b}=" not in r_exp.output:
                raise RuntimeError("export did not include the test secret name.")

        def step_dump_apply_pair():
            r_dump = invoke_in_dir(t1, ["dump"])
            if r_dump.exit_code != 0:
                raise RuntimeError(f"dump failed:\n{r_dump.output}")
            dump_json = r_dump.output
            if not dump_json.strip().startswith("{"):
                raise RuntimeError("dump did not produce JSON.")

            r_apply = invoke_in_dir(t2, ["dump-apply", "--yes"], input_text=dump_json)
            if r_apply.exit_code != 0:
                raise RuntimeError(f"dump-apply failed:\n{r_apply.output}")

            r_get2 = invoke_in_dir(t2, ["get", b])
            if r_get2.exit_code != 0:
                raise RuntimeError(f"get(after dump-apply) failed:\n{r_get2.output}")
            if r_get2.output != val:
                raise RuntimeError("get(after dump-apply) output mismatch.")

        def step_rotate_then_get():
            r_rot = invoke_in_dir(t1, ["rotate", "--yes"])
            if r_rot.exit_code != 0:
                raise RuntimeError(f"rotate failed:\n{r_rot.output}")

            r_get = invoke_in_dir(t1, ["get", b])
            if r_get.exit_code != 0:
                raise RuntimeError(f"get(after rotate) failed:\n{r_get.output}")
            if r_get.output != val:
                raise RuntimeError("get(after rotate) output mismatch.")

        def step_rm():
            r_rm = invoke_in_dir(t1, ["rm", b], input_text="y\n")
            if r_rm.exit_code != 0:
                raise RuntimeError(f"rm failed:\n{r_rm.output}")

            r_get = invoke_in_dir(t1, ["get", b])
            if r_get.exit_code == 0:
                raise RuntimeError("get succeeded after rm (expected failure).")

        steps += [
            ("list", step_list_empty_or_ok),
            ("set/get", step_set_get),
            ("set/get multiline from file", step_set_from_file_multiline),
            ("mv + verify", step_mv_and_verify),
            ("comment/export", step_comment_and_export),
            ("dump -> dump-apply (paired)", step_dump_apply_pair),
            ("rotate -> get", step_rotate_then_get),
            ("rm -> verify missing", step_rm),
        ]

        total = len(steps)
        click.echo(f"\U0001f50e Running self-test in temp stores (real secrets untouched).")

        for i, (name, fn) in enumerate(steps, start=1):
            click.echo(f"[{i}/{total}] Testing: {name} ... ", nl=False)
            try:
                fn()
                click.echo("OK")
            except Exception as e:
                click.echo("FAILED")
                click.echo(f"   Error: {e}")
                if keep_temp:
                    click.echo(f"   Temp dirs kept:\n     t1={t1}\n     t2={t2}")
                raise click.ClickException("Self-test failed.") from e

        click.echo("\u2705 Self-test passed.")
        if keep_temp:
            click.echo(f"Temp dirs kept:\n  t1={t1}\n  t2={t2}")

    finally:
        if not keep_temp:
            t1_td.cleanup()
            t2_td.cleanup()


if __name__ == "__main__":
    cli()
