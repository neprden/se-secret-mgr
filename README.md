# se-mgr

`se-mgr` is a small CLI secret manager.

It stores:
- `master.key` (age identity, usually via `age-plugin-se` / Secure Enclave)
- `MASTER.age` (age-encrypted base64 AES-256 key)
- `*.enc` secrets (AES-256-GCM, with optional description metadata)

## Features

- AES-256-GCM encryption for secrets
- `master.key` + `MASTER.age` key model
- Secret descriptions (`comment`, `list --long`)
- Read secret from prompt or file (`set --from-file`)
- Multiline secret support from file/stdin
- Key rotation (`rotate`)
- Portable export/import (`dump` / `dump-apply`)
- Clipboard copy (`pbcopy`, requires `pyperclip`)
- Built-in self-test (`test`)

## Requirements

- Python 3.10+
- `age`
- `openssl`
- Python packages:
  - `click`
  - `cryptography`
  - `pyperclip` (optional, only for `pbcopy`)

Install Python deps:

```bash
pip install click cryptography pyperclip
```

## Quick Start

### 1. Create a secrets directory

```bash
mkdir -p ~/.secrets
```

### 2. Generate identity key

Secure Enclave (recommended):

```bash
age-plugin-se keygen -o ~/.secrets/master.key
```

Alternative for non-SE environments:

```bash
age-keygen -o ~/.secrets/master.key
```

### 3. Create shared AES master key (`MASTER.age`)

```bash
age -r "$(grep -m1 '^# public key:' ~/.secrets/master.key | awk '{print $4}')" \
  -o ~/.secrets/MASTER.age <(openssl rand -base64 32)
```

### 4. Store and read secrets

```bash
python3 se-mgr.py set API_TOKEN
python3 se-mgr.py get API_TOKEN
```

## Usage

Global options:

```bash
python3 se-mgr.py --help
python3 se-mgr.py --secrets-dir /path/to/secrets <command>
```

Main commands:

- `set NAME` - store/update a secret
- `get NAME` - print decrypted secret
- `list [-l|--long]` - list secret names (and descriptions in YAML)
- `comment NAME [DESCRIPTION] [--stdin|--file FILE]` - set description
- `export` - print `export NAME='value'` lines
- `mv OLD NEW` - rename secret
- `rm NAME` - delete secret
- `rotate [--yes]` - rotate AES master key and re-encrypt all secrets
- `dump [--pretty]` - output portable JSON dump (contains plaintext master key in base64)
- `dump-apply [--yes]` - apply dump JSON from stdin
- `pbcopy NAME [--clear-after N]` - copy secret to clipboard
- `master` - show setup checklist/help
- `test [--keep-temp] [-v|--verbose]` - run built-in self-test

## Multiline Secret Input

Interactive prompt is intended for single-line values. For multiline values, use file/stdin input:

From file:

```bash
python3 se-mgr.py set TLS_CERT --from-file ./cert.pem
```

From stdin:

```bash
cat cert.pem | python3 se-mgr.py set TLS_CERT --from-file -
```

## Description Metadata

Set/update description:

```bash
python3 se-mgr.py comment API_TOKEN "GitHub token for CI"
```

Multiline description from stdin:

```bash
cat desc.txt | python3 se-mgr.py comment API_TOKEN --stdin
```

Show descriptions:

```bash
python3 se-mgr.py list --long
```

## Security Notes

- `dump` output is highly sensitive because it includes `master_key_b64`.
- Keep `~/.secrets` protected and backed up securely.
- Avoid printing secrets into shell history when possible.
- Clipboard contents can be exposed by other processes; use `--clear-after` where needed.

## Development

Run internal self-test:

```bash
python3 se-mgr.py test
```

This uses temporary directories and does not touch real secrets.

Install project locally (creates `.venv`):

```bash
make install
```

Run unit tests:

```bash
make test
```

Run coverage check (fails under 35%):

```bash
make coverage
```

Install test dependencies:

```bash
pip install -e .[test]
```
