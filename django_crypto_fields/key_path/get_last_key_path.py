import csv
import sys
from pathlib import Path, PurePath

from .key_path import KeyPath

__all__ = ["get_last_key_path"]


def get_last_key_path(filename: str | PurePath) -> PurePath | None:
    """Get last used DJANGO_CRYPTO_FIELDS_KEY_PATH from
    django_crypto_fields file in the key_path folder.
    """
    last_used_path: PurePath | None = None
    path = Path(KeyPath().path / filename)
    if path.exists():
        if "runtests.py" in sys.argv:
            path.unlink()  # delete the file
        else:
            with path.open(mode="r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # use first row only
                    last_used_path = PurePath(row.get("path"))
                    break
    return last_used_path
