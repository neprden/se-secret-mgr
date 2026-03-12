import re
from pathlib import Path

NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9_]+$")

DEFAULT_SECRETS_DIR = Path.home() / ".secrets"
MASTER_IDENTITY = "master.key"   # age identity (SE/TouchID protected)
MASTER_AGE = "MASTER.age"        # age-encrypted base64(AES-256 key)
ENC_EXT = ".enc"

MAGIC = b"SEMG1"       # format marker
NONCE_LEN = 12         # AESGCM nonce length
DUMP_VERSION = 1

ENC_JSON_VERSION = 1   # .enc JSON container version
