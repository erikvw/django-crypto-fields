import os
import sys

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django_crypto_fields.constants import style

from .constants import RSA, AES, SALT, PRIVATE, PUBLIC, RESTRICTED_MODE, LOCAL_MODE
from .default_key_path import default_key_path


class DjangoCryptoFieldsKeyPathError(Exception):
    pass


class KeyPathHandler:
    """KEY_FILENAME names the algorithm (rsa, aes or salt), the mode (local and
    restricted) and the paths of the files to be created.

    The default KEY_FILENAME dictionary refers to 8 files.
       - 2 RSA local (public, private)
       - 2 RSA restricted  (public, private)
       - 1 AES local (RSA encrypted)
       - 1 AES restricted (RSA encrypted)
       - 1 salt local (RSA encrypted).
       - 1 salt restricted (RSA encrypted)."""

    def __init__(self, key_path=None, key_prefix=None):
        self.using_test_keys = False
        self._key_path = None
        self._key_prefix = None
        self.key_path = key_path
        self.key_prefix = key_prefix

    @property
    def key_filenames(self):
        return {
            RSA: {
                RESTRICTED_MODE: {
                    PUBLIC: os.path.join(
                        self.key_path, self.key_prefix + '-rsa-restricted-public.pem'),
                    PRIVATE: os.path.join(
                        self.key_path, self.key_prefix + '-rsa-restricted-private.pem')},
                LOCAL_MODE: {
                    PUBLIC: os.path.join(
                        self.key_path, self.key_prefix + '-rsa-local-public.pem'),
                    PRIVATE: os.path.join(
                        self.key_path, self.key_prefix + '-rsa-local-private.pem')}},
            AES: {
                LOCAL_MODE: {
                    PRIVATE: os.path.join(
                        self.key_path, self.key_prefix + '-aes-local.key')},
                RESTRICTED_MODE: {
                    PRIVATE: os.path.join(
                        self.key_path, self.key_prefix + '-aes-restricted.key')}},
            SALT: {
                LOCAL_MODE: {
                    PRIVATE: os.path.join(
                        self.key_path, self.key_prefix + '-salt-local.key')},
                RESTRICTED_MODE: {
                    PRIVATE: os.path.join(
                        self.key_path, self.key_prefix + '-salt-restricted.key')}},
        }

    @property
    def key_files_exist(self):
        key_files_exist = True
        for group, key_group in self.key_filenames.items():
            for mode, keys in key_group.items():
                for key in keys:
                    if not os.path.exists(self.key_filenames[group][mode][key]):
                        key_files_exist = False
                        break
        return key_files_exist

    @property
    def key_path(self):
        return self._key_path

    @key_path.setter
    def key_path(self, key_path=None):
        """Set the key_path, if None, try to set from settings (default).
        """
        if not key_path:
            try:
                key_path = settings.KEY_PATH
            except AttributeError:
                try:
                    key_path = default_key_path
                    sys.stdout.write(style.WARNING(
                        f'Warning! Not ready for production. Setting KEY_PATH '
                        f'to {key_path} for testing purposes.\n'))
                    self.using_test_keys = True
                except (ImproperlyConfigured, AttributeError):
                    # your not in Django ...
                    # you should have passed a key_path to this setter
                    raise DjangoCryptoFieldsKeyPathError(
                        'Cannot determine the key path.')
        key_path = os.path.expanduser(str(key_path))
        if not os.path.exists(key_path):
            raise DjangoCryptoFieldsKeyPathError(
                f'Invalid key path. Got {key_path}')
        self._key_path = key_path

    @property
    def key_prefix(self):
        return self._key_prefix

    @key_prefix.setter
    def key_prefix(self, key_prefix):
        if self.using_test_keys:
            self._key_prefix = 'test'
        else:
            self._key_prefix = key_prefix or 'user'
