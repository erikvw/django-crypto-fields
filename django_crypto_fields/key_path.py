import os

from django.conf import settings
from django.core.management.color import color_style
from tempfile import mkdtemp

from .persist_key_path import persist_key_path


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
    temp_key_path_for_tests = mkdtemp()

    def __init__(self, key_path=None, key_prefix=None, force_key_path=None, use_temp_path=None):
        self.key_path = key_path
        self.key_prefix = key_prefix or self.default_key_prefix
        self.temp_path = None

        if use_temp_path and not force_key_path:
            self.key_path = self.temp_key_path_for_tests
            self.temp_path = self.key_path
        else:
            if not self.key_path:
                try:
                    self.key_path = settings.KEY_PATH
                except AttributeError:
                    if settings.DEBUG:
                        self.key_path = self.non_production_path
                if not self.key_path:
                    raise DjangoCryptoFieldsKeyPathError(
                        f'Invalid key path. Production systems must explicitly '
                        f'set a path other than the default non-production path [DEBUG={settings.DEBUG}, '
                        f'KEY_PATH==\'{self.key_path}\', '
                        f'non-production path == \'{self.non_production_path}\']. ')

        if self.key_path == self.non_production_path:
            self.using_test_keys = True
        if not self.key_path:
            raise DjangoCryptoFieldsKeyPathError(
                'Cannot determine the key path.')

        self.key_path = os.path.expanduser(str(self.key_path))
        if not os.path.exists(self.key_path):
            raise DjangoCryptoFieldsKeyPathDoesNotExist(
                f'Encryption key path does not exist. Got {self.key_path}')
#         if not use_temp_path:
#             persist_key_path(key_path=self.key_path, filename=os.path.join(
#                 settings.ETC_DIR, 'django_crypto_fields'))
