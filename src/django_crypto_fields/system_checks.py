import os

from django.core.checks import CheckMessage, Warning  # noqa: A004

from .utils import get_keypath_from_settings


def check_key_path(app_configs, **kwargs) -> list[CheckMessage]:  # noqa: ARG001
    errors = []
    key_path = get_keypath_from_settings()
    if key_path and os.access(key_path, os.W_OK):
        errors.append(
            Warning(
                f"Insecure configuration. Folder is writeable by this user. Got {key_path}",
                id="settings.DJANGO_CRYPTO_FIELDS_KEY_PATH",
            )
        )
    return errors
