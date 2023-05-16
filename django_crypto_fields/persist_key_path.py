import csv
import os
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

from django.apps import apps as django_apps
from django.conf import settings
from django.core.management.color import color_style

style = color_style()


class DjangoCryptoFieldsKeyPathError(Exception):
    pass


class DjangoCryptoFieldsKeyPathChangeError(Exception):
    pass


def get_etc_dir(no_warn=None):
    etc_dir = getattr(settings, "ETC_DIR", None)
    if not etc_dir and not settings.DEBUG:
        if not no_warn:
            raise DjangoCryptoFieldsKeyPathError(
                "ETC_DIR not set for DEBUG=False. See Settings.ETC_DIR."
            )
    else:
        etc_dir = getattr(settings, "ETC_DIR", f"{os.path.join(settings.BASE_DIR, '.etc')}")
    return etc_dir


def get_last_key_path(filename=None):
    last_key_path = None
    if "test" not in sys.argv:
        if not filename:
            app_config = django_apps.get_app_config("django_crypto_fields")
            filename = app_config.last_key_path_filename

        filepath = os.path.join(get_etc_dir(), filename)
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    last_key_path = row.get("path")
                    break
    return last_key_path


def persist_key_path(key_path=None, filename=None):
    last_key_path = get_last_key_path(filename)

    if not last_key_path:
        with open(filename, "w") as f:
            writer = csv.DictWriter(f, fieldnames=["path", "date"])
            writer.writeheader()
            writer.writerow(
                dict(path=key_path.path, date=datetime.now().astimezone(ZoneInfo("UTC")))
            )
        last_key_path = key_path.path
    else:
        if not os.path.exists(last_key_path):
            raise DjangoCryptoFieldsKeyPathError(
                style.ERROR(f"Invalid last key path. See {filename}. Got {last_key_path}")
            )
    if last_key_path != key_path.path:
        raise DjangoCryptoFieldsKeyPathChangeError(
            style.ERROR(
                "Key path changed since last startup! You must resolve "
                "this before using the system. Using the wrong keys will "
                "corrupt your data."
            )
        )
