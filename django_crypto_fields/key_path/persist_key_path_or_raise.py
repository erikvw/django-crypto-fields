import csv
import sys
from datetime import datetime
from pathlib import Path, PurePath
from zoneinfo import ZoneInfo

from django.core.management import color_style

from ..exceptions import (
    DjangoCryptoFieldsKeyPathChangeError,
    DjangoCryptoFieldsKeyPathError,
)
from .key_path import KeyPath

__all__ = ["persist_key_path_or_raise"]


def persist_key_path_or_raise() -> None:
    expected_folder: Path = Path(KeyPath().path)
    last_used_folder, filepath = read_last_used(expected_folder)
    if not last_used_folder:
        last_used_folder = write_last_used(filepath)
    if last_used_folder != expected_folder:
        style = color_style()
        raise DjangoCryptoFieldsKeyPathChangeError(
            style.ERROR(
                "Key path changed since last startup! You must resolve "
                "this before using the system. Using the wrong keys will "
                "corrupt your data."
            )
        )


def write_last_used(filepath: Path) -> Path:
    """Write the last used path in file `django_crypto_fields`."""
    with filepath.open(mode="w") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "date"])
        writer.writeheader()
        writer.writerow(
            dict(path=filepath.parent, date=datetime.now().astimezone(ZoneInfo("UTC")))
        )
    return filepath.parent


def read_last_used(folder: Path) -> tuple[PurePath | None, Path]:
    """Opens file `django_crypto_fields` and read last path."""
    last_used_path = None
    filepath = Path(folder / "django_crypto_fields")
    if "runtests.py" in sys.argv:
        filepath.unlink(missing_ok=True)
    elif filepath.exists():
        with filepath.open(mode="r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                last_used_path = PurePath(row.get("path"))
                break
    if last_used_path and not Path(last_used_path).exists():
        style = color_style()
        raise DjangoCryptoFieldsKeyPathError(
            style.ERROR(
                "Last path used to access encryption keys is invalid. "
                f"See file `{filepath}`. Got `{last_used_path}`"
            )
        )
    return last_used_path, filepath
