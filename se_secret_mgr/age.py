import subprocess
from pathlib import Path

from .utils import die, run_checked


class AgeBackend:
    @staticmethod
    def decrypt(identity_file: Path, master_age_file: Path) -> bytes:
        p = run_checked(["age", "-d", "-i", str(identity_file), str(master_age_file)])
        return p.stdout

    @staticmethod
    def get_recipient(identity_file: Path) -> str:
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

    @staticmethod
    def encrypt_to_recipient(recipient: str, plaintext: bytes) -> bytes:
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
