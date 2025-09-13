from __future__ import annotations

import itertools
import sys
from dataclasses import dataclass, field
from pathlib import PurePath
from tempfile import mkdtemp

from django.conf import settings

from ..exceptions import (
    DjangoCryptoFieldsKeyPathDoesNotExist,
    DjangoCryptoFieldsKeyPathError,
)
from ..utils import get_keypath_from_settings, get_test_module_from_settings

__all__ = ["KeyPath"]

KEY_PATH_DOES_NOT_EXIST = (
    "Path to encryption keys does not exist. "
    "See settings.DJANGO_CRYPTO_FIELDS_KEY_PATH. "
    "Got '{invalid_path}'."
)
KEY_PATH_IN_APP_FOLDER = (
    "Invalid path to encryption keys. Path cannot be in an app folder. "
    "See settings.DJANGO_CRYPTO_FIELDS_KEY_PATH. "
    "Got '{invalid_path}'."
)

KEY_PATH_IS_NONE = (
    "Path may not be none. Production or debug systems must explicitly "
    "set a valid path to the encryption keys. "
    "See settings.DJANGO_CRYPTO_FIELDS_KEY_PATH."
)


@dataclass
class KeyPath:
    """A class to set/determine the correct key_path.

    If this is called during a test, the value of `settings.DEBUG` sets
    the value of settings.DJANGO_CRYPTO_FIELDS_KEY_PATH to a tempdir
    if not set explicitly.
    """

    path: PurePath | None = field(default=None, init=False)

    def __post_init__(self):
        path = get_keypath_from_settings()
        if not path:
            path = self.create_folder_for_tests_or_raise()
        elif not path.exists():
            raise DjangoCryptoFieldsKeyPathDoesNotExist(
                KEY_PATH_DOES_NOT_EXIST.format(invalid_path=str(path))
            )
        if (
            not settings.DEBUG
            and (
                get_test_module_from_settings()
                not in list(itertools.chain(*[x.split("/") for x in sys.argv]))
            )
            and str(settings.BASE_DIR) in str(path)
        ):
            raise DjangoCryptoFieldsKeyPathError(
                KEY_PATH_IN_APP_FOLDER.format(invalid_path=str(path))
            )
        self.path = PurePath(path)

    def __str__(self) -> str:
        return str(self.path)

    @staticmethod
    def create_folder_for_tests_or_raise() -> PurePath:
        if get_test_module_from_settings() in list(
            itertools.chain(*[x.split("/") for x in sys.argv])
        ):
            path = PurePath(mkdtemp())
        else:
            raise DjangoCryptoFieldsKeyPathError(KEY_PATH_IS_NONE)
        return path
