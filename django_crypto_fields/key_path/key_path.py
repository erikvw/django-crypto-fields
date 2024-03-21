from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from tempfile import mkdtemp

from django.conf import settings

from ..exceptions import (
    DjangoCryptoFieldsKeyPathDoesNotExist,
    DjangoCryptoFieldsKeyPathError,
)
from ..utils import get_keypath_from_settings, get_test_module_from_settings

__all__ = ["KeyPath"]


@dataclass
class KeyPath:
    """A class to set/determine the correct key_path.

    if this is called during a test, the value of `settings.DEBUG` sets
    the value of settings.DJANGO_CRYPTO_FIELDS_KEY_PATH to a tempdir
    if not set explicitly.
    """

    path: PurePath | None = field(default=None, init=False)

    def __post_init__(self):
        path = get_keypath_from_settings()
        if not path:
            path = self.create_folder_for_tests_or_raise()
        elif not Path(path).exists():
            raise DjangoCryptoFieldsKeyPathDoesNotExist(
                "Path to encryption keys does not exist. "
                "settings.DJANGO_CRYPTO_FIELDS_KEY_PATH='"
                f"{get_keypath_from_settings()}'. "
                f"Got '{path}'."
            )
        if (
            not settings.DEBUG
            and get_test_module_from_settings() not in sys.argv
            and str(settings.BASE_DIR) in str(path)
        ):
            raise DjangoCryptoFieldsKeyPathError(
                "Invalid production path. Path cannot be in an app folder. "
                "See settings.DJANGO_CRYPTO_FIELDS_KEY_PATH. "
                f"Got '{path}'."
            )
        self.path = PurePath(path)

    def __str__(self) -> str:
        return str(self.path)

    @staticmethod
    def create_folder_for_tests_or_raise() -> PurePath:
        if get_test_module_from_settings() in sys.argv:
            path = PurePath(mkdtemp())
        else:
            raise DjangoCryptoFieldsKeyPathError(
                "Path may not be none. Production or debug systems must explicitly "
                "set a valid path to the encryption keys. "
                "See settings.DJANGO_CRYPTO_FIELDS_KEY_PATH."
            )
        return path
