import csv
import os

from django.apps import apps as django_apps
from django.conf import settings
from django.core.management.color import color_style
from edc_base.utils import get_utcnow

style = color_style()


class DjangoCryptoFieldsKeyPathChangeError(Exception):
    pass


def persist_key_path(key_path=None, filename=None):
    if not filename:
        app_config = django_apps.get_app_config('django_crypto_fields')
        filename = app_config.last_key_path_filename

    filepath = os.path.join(settings.ETC_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                last_key_path = row.get('path')
                break
    else:
        with open(filename, 'w') as f:
            writer = csv.DictWriter(f, fieldnames=['path', 'date'])
            writer.writeheader()
            writer.writerow(dict(path=key_path.path, date=get_utcnow()))
        last_key_path = key_path.path

    if last_key_path != key_path.path:
        raise DjangoCryptoFieldsKeyPathChangeError(style.ERROR(
            f'Key path changed since last startup! You must resolve '
            f'this before using the system. Using the wrong keys will corrupt your data.'))
