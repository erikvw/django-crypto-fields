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
    last_used_path: PurePath | None = None
    path: Path = Path(KeyPath().path)
    file = Path(path / "django_crypto_fields")
    if file.exists():
        if "runtests.py" in sys.argv:
            file.unlink()  # delete the file
        else:
            # open file `django_crypto_fields` and read last path
            with file.open(mode="r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # use first row only
                    last_used_path = PurePath(row.get("path"))
                    break
    if not last_used_path:
        # persist the path in file `django_crypto_fields`
        with file.open(mode="w") as f:
            writer = csv.DictWriter(f, fieldnames=["path", "date"])
            writer.writeheader()
            writer.writerow(dict(path=path, date=datetime.now().astimezone(ZoneInfo("UTC"))))
        last_used_path = path
    else:
        if not Path(last_used_path).exists():
            style = color_style()
            raise DjangoCryptoFieldsKeyPathError(
                style.ERROR(f"Invalid last key path. See {file}. Got {last_used_path}")
            )
    if last_used_path != path:
        style = color_style()
        raise DjangoCryptoFieldsKeyPathChangeError(
            style.ERROR(
                "Key path changed since last startup! You must resolve "
                "this before using the system. Using the wrong keys will "
                "corrupt your data."
            )
        )
