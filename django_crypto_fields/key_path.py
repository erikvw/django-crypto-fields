import os

from django.conf import settings
from django.core.management.color import color_style


class DjangoCryptoFieldsKeyPathError(Exception):
    pass


class DjangoCryptoFieldsKeyPathDoesNotExist(Exception):
    pass


class DjangoCryptoFieldsKeyPathChangeError(Exception):
    pass


style = color_style()


class KeyPath:
    """A class to set/determine the correct key_path.

    if this is called during a test, the value of settings.DEBUG sets
    the value of settings.KEY_PATH to a tempdir if not set explicitly.
    """

    default_key_prefix = "user"

    # path for non-production use with runserver
    non_production_path = os.path.join(settings.BASE_DIR, "crypto_fields")

    def __init__(self, path=None, key_prefix=None):
        self.key_prefix = key_prefix or self.default_key_prefix
        # if "test" in sys.argv or "tox" in sys.argv:
        #     path = path or self.non_production_path
        # else:
        path = path or settings.KEY_PATH
        self.path = self._is_valid(path)
        if not self.path:
            raise DjangoCryptoFieldsKeyPathError(
                f"Invalid key path. Production systems must explicitly "
                f"set a path other than the default non-production path "
                f"[DEBUG={settings.DEBUG}, "
                f"KEY_PATH=='{self.path}', "
                f"settings.KEY_PATH=='{settings.KEY_PATH}', "
                f"non-production path == '{self.non_production_path}']. "
            )
        if self.path == self.non_production_path:
            self.using_test_keys = True
        if not self.path:
            raise DjangoCryptoFieldsKeyPathError("Cannot determine the key path.")

    def __str__(self):
        return self.path

    def _is_valid(self, path):
        """Returns the path or raises.
        """
        path = path or ""
        if settings.DEBUG is False and path == self.non_production_path:
            raise DjangoCryptoFieldsKeyPathError(
                f"Invalid key path. Key path may not be the default "
                f"non-production path if DEBUG=False. Got {self.non_production_path}"
            )
        elif not path or not os.path.exists(path):
            raise DjangoCryptoFieldsKeyPathDoesNotExist(
                f"Key path does not exist. Got '{path}'"
            )
        return path
