import os

from django.conf import settings
from django.core.management.color import color_style
from tempfile import mkdtemp
from django.urls.conf import path


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
    the value of settings.KEY_PATH to a tempdir
    """

    default_key_prefix = 'user'

    # path for non-production use with runserver
    non_production_path = os.path.join(settings.BASE_DIR, 'crypto_fields')
    # path for tests
    # temp_path = mkdtemp()

    def __init__(self, path=None, key_prefix=None):
        self._path = None
        self.key_prefix = key_prefix or self.default_key_prefix
        if path:
            self.path = path
        else:
            try:
                self.path = settings.KEY_PATH
            except AttributeError:
                if settings.DEBUG:
                    self.path = self.non_production_path
            else:
                if settings.DEBUG and self.path:
                    raise DjangoCryptoFieldsKeyPathError(
                        f'Invalid key path. settings.KEY_PATH may not be set if DEBUG=True.')
            if not self.path:
                raise DjangoCryptoFieldsKeyPathError(
                    f'Invalid key path. Production systems must explicitly '
                    f'set a path other than the default non-production path [DEBUG={settings.DEBUG}, '
                    f'KEY_PATH==\'{self.path}\', '
                    f'non-production path == \'{self.non_production_path}\']. ')

        if self.path == self.non_production_path:
            self.using_test_keys = True
        if not self.path:
            raise DjangoCryptoFieldsKeyPathError(
                'Cannot determine the key path.')

    def __str__(self):
        return self.path

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        if not value or not os.path.exists(value):
            raise DjangoCryptoFieldsKeyPathDoesNotExist(
                f'Key path \'{value}\' does not exist.')
        elif not settings.DEBUG and value == self.non_production_path:
            raise DjangoCryptoFieldsKeyPathError(
                f'Invalid key path. Key path may not be the default '
                f'non-production path if DEBUG=False. Got {self.non_production_path}')
        else:
            self._path = value
