import os
import sys

from django.conf import settings
from django.db import connection
from tempfile import mkdtemp

from .constants import style


class DjangoCryptoFieldsKeyPathError(Exception):
    pass


class DjangoCryptoFieldsKeyPathDoesNotExist(Exception):
    pass


class DjangoCryptoFieldsKeyPathChangeError(Exception):
    pass


class KeyPath:

    """A class to set/determine the correct key_path.

    Considers if this is called during a test, the value of settings.DEBUG,
    and the value of settings.KEY_PATH.
    """

    non_production_path = os.path.join(settings.BASE_DIR, 'crypto_fields')
    default_key_prefix = 'user'
    temp_key_path_for_tests = mkdtemp()

    def __init__(self, key_path=None, key_prefix=None, force_key_path=None,
                 persist_key_path=None, use_temp_path=None):
        self.key_path = key_path
        self.key_prefix = key_prefix or self.default_key_prefix
        self.temp_path = None

        if use_temp_path and not force_key_path:
            self.key_path = self.temp_key_path_for_tests
            self.temp_path = self.key_path
        else:
            if not self.key_path:
                try:
                    settings_key_path = settings.KEY_PATH
                except AttributeError:
                    settings_key_path = self.non_production_path
                self.key_path = (
                    self.non_production_path if settings.DEBUG else settings_key_path)
                if (self.key_path == self.non_production_path) and not settings.DEBUG:
                    raise DjangoCryptoFieldsKeyPathError(
                        f'Invalid key path. Production systems must explicitly '
                        f'set a path other than the non-production path [DEBUG={settings.DEBUG}, '
                        f'KEY_PATH==\'{settings_key_path}\', '
                        f'non-production path == \'{self.non_production_path}\']. '
                        f'Got \'{self.key_path}\'.')

        if self.key_path == self.non_production_path:
            sys.stdout.write(style.WARNING(
                f'Warning! Not ready for production. Setting key path '
                f'to non-production path {self.key_path}.\n'))
            self.using_test_keys = True
        if not self.key_path:
            raise DjangoCryptoFieldsKeyPathError(
                'Cannot determine the key path.')

        self.key_path = os.path.expanduser(str(self.key_path))
        if not os.path.exists(self.key_path):
            raise DjangoCryptoFieldsKeyPathDoesNotExist(
                f'Encryption key path does not exist. Got {self.key_path}')
        if persist_key_path:
            self.persist_key_path()

    def persist_key_path(self):
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT id, key_path FROM django_crypto_fields_keyreference')
            row = cursor.fetchone()
            if row:
                print(row[1])
                if row[1] != self.key_path:
                    raise DjangoCryptoFieldsKeyPathError(
                        f'Key path has changed. Expected {row[1]}. Got {self.key_path}')
            else:
                cursor.execute(
                    'INSERT INTO `django_crypto_fields_keyreference` (key_path) '
                    'VALUES (%s)', [self.key_path])
