import os

from django.conf import settings
from django.core.checks import CheckMessage, Warning


def check_key_path(app_configs, **kwargs) -> list[CheckMessage]:
    errors = []
    try:
        settings.DJANGO_CRYPTO_FIELDS_KEY_PATH
    except AttributeError:
        pass
    else:
        if settings.DJANGO_CRYPTO_FIELDS_KEY_PATH and os.access(
            settings.DJANGO_CRYPTO_FIELDS_KEY_PATH, os.W_OK
        ):
            errors.append(
                Warning(
                    "Insecure configuration. Folder is writeable by this user. "
                    f"Got {settings.DJANGO_CRYPTO_FIELDS_KEY_PATH}",
                    id="settings.DJANGO_CRYPTO_FIELDS_KEY_PATH",
                )
            )
    return errors
