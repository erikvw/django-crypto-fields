import os
import copy
import sys

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA as RSA_PUBLIC_KEY
from Crypto.Util import number

from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, AppRegistryNotReady
from django_crypto_fields.apps import DjangoCryptoFieldsError
from django_crypto_fields.constants import style
from django_crypto_fields.exceptions import DjangoCryptoFieldsKeysAlreadyLoaded

from .constants import RSA, AES, SALT, PRIVATE, PUBLIC, RSA_KEY_SIZE, RESTRICTED_MODE, LOCAL_MODE


class KeyPathMixin:
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
        """Set the key_path, if None, try to set from settings (default)."""
        if not key_path:
            try:
                key_path = settings.KEY_PATH
            except (ImproperlyConfigured, AttributeError):
                try:
                    key_path = settings.BASE_DIR
                    sys.stdout.write(style.WARNING(
                        'Warning! Not ready for production. Setting KEY_PATH to {} '
                        'for testing purposes.'.format(key_path)))
                    self.using_test_keys = True
                except (ImproperlyConfigured, AttributeError):
                    # your not in Django ...
                    # you should have passed a key_path to this setter
                    raise DjangoCryptoFieldsError('Cannot determine the key path.')
        key_path = os.path.expanduser(key_path)
        if not os.path.exists(key_path):
            raise DjangoCryptoFieldsError('Invalid key path. Got {}'.format(key_path))
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

    @property
    def key_filenames(self):
        return {
            RSA: {
                RESTRICTED_MODE: {
                    PUBLIC: os.path.join(self.key_path, self.key_prefix + '-rsa-restricted-public.pem'),
                    PRIVATE: os.path.join(self.key_path, self.key_prefix + '-rsa-restricted-private.pem')},
                LOCAL_MODE: {
                    PUBLIC: os.path.join(self.key_path, self.key_prefix + '-rsa-local-public.pem'),
                    PRIVATE: os.path.join(self.key_path, self.key_prefix + '-rsa-local-private.pem')}},
            AES: {
                LOCAL_MODE: {
                    PRIVATE: os.path.join(self.key_path, self.key_prefix + '-aes-local.key')},
                RESTRICTED_MODE: {
                    PRIVATE: os.path.join(self.key_path, self.key_prefix + '-aes-restricted.key')}},
            SALT: {
                LOCAL_MODE: {
                    PRIVATE: os.path.join(self.key_path, self.key_prefix + '-salt-local.key')},
                RESTRICTED_MODE: {
                    PRIVATE: os.path.join(self.key_path, self.key_prefix + '-salt-restricted.key')}},
        }


class Keys(KeyPathMixin):

    keys_are_ready = False
    rsa_key_info = {}

    """
    Class to prepare RSA, AES keys for use by field classes.

        * Keys are imported through the AppConfig __init__ method.
        * Keys are create through the AppConfig __init__ method, if necessary.
    """

    def __init__(self, key_path=None, key_prefix=None):
        super(Keys, self).__init__(key_path, key_prefix)
        self._keys = copy.deepcopy(self.key_filenames)
        self.rsa_modes_supported = sorted([k for k in self._keys[RSA]])
        self.aes_modes_supported = sorted([k for k in self._keys[AES]])

    def create_keys(self):
        """Generates RSA and AES keys as per `key_filenames`."""
        sys.stdout.write(style.NOTICE('Generating new keys ...\n'))
        self.create_rsa()
        self.create_aes()
        self.create_salt()
        sys.stdout.write(style.SUCCESS('Done.\n'))

    def load_keys(self):
        """Loads all keys defined in self.key_filenames."""
        try:
            if django_apps.get_app_config('django_crypto_fields').encryption_keys:
                raise DjangoCryptoFieldsKeysAlreadyLoaded()
        except (AppRegistryNotReady, AttributeError):
            pass
        if not self.keys_are_ready:
            sys.stdout.write(' * loading keys from {}\n'.format(self.key_path))
            for mode, keys in self.key_filenames[RSA].items():
                for key in keys:
                    sys.stdout.write(' * loading {}.{}.{} ...\r'.format(RSA, mode, key))
                    self.load_rsa_key(mode, key)
                    sys.stdout.write(' * loading {}.{}.{} ... Done.\n'.format(RSA, mode, key))
            for mode in self.key_filenames[AES]:
                sys.stdout.write(' * loading {}.{} ...\r'.format(AES, mode))
                self.load_aes_key(mode)
                sys.stdout.write(' * loading {}.{} ... Done.\n'.format(AES, mode))
            for mode in self.key_filenames[SALT]:
                sys.stdout.write(' * loading {}.{} ...\r'.format(SALT, mode))
                self.load_salt_key(mode, key)
                sys.stdout.write(' * loading {}.{} ... Done.\n'.format(SALT, mode))
            self.keys_are_ready = True

    def load_rsa_key(self, mode, key):
        """Loads an RSA key into _keys."""
        key_file = self.key_filenames[RSA][mode][key]
        with open(key_file, 'rb') as frsa:
            rsa_key = RSA_PUBLIC_KEY.importKey(frsa.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            self._keys[RSA][mode][key] = rsa_key
            self.update_rsa_key_info(rsa_key, mode)
        setattr(self, RSA + '_' + mode + '_' + key + '_key', rsa_key)
        return key_file

    def load_aes_key(self, mode):
        """Decrypts and loads an AES key into _keys.

        Note: AES does not use a public key."""
        key = PRIVATE
        rsa_key = self._keys[RSA][mode][key]
        try:
            key_file = self.key_filenames[AES][mode][key]
        except KeyError:
            print(self.key_filenames.get(AES))
            raise
        with open(key_file, 'rb') as faes:
            aes_key = rsa_key.decrypt(faes.read())
        self._keys[AES][mode][key] = aes_key
        setattr(self, AES + '_' + mode + '_' + key + '_key', aes_key)
        return key_file

    def load_salt_key(self, mode, key):
        """Decrypts and loads a salt key into _keys."""
        attr = SALT + '_' + mode + '_' + PRIVATE
        rsa_key = self._keys[RSA][mode][PRIVATE]
        key_file = self.key_filenames[SALT][mode][PRIVATE]
        with open(key_file, 'rb') as fsalt:
            salt = rsa_key.decrypt(fsalt.read())
            setattr(self, attr, salt)
        return key_file

    def update_rsa_key_info(self, rsa_key, mode):
        """Stores info about the RSA key."""
        modBits = number.size(rsa_key._key.n)
        self.rsa_key_info[mode] = {'bits': modBits}
        k = number.ceil_div(modBits, 8)
        self.rsa_key_info[mode].update({'bytes': k})
        hLen = rsa_key._hashObj.digest_size
        self.rsa_key_info[mode].update({'max_message_length': k - (2 * hLen) - 2})

    def create_rsa(self, mode=None):
        """Creates RSA keys."""
        modes = [mode] if mode else self.key_filenames.get(RSA)
        for mode in modes:
            key = RSA_PUBLIC_KEY.generate(RSA_KEY_SIZE)
            pub = key.publickey()
            path = self.key_filenames.get(RSA).get(mode).get(PUBLIC)
            try:
                with open(path, 'xb') as fpub:
                    fpub.write(pub.exportKey('PEM'))
                sys.stdout.write(' - Created new RSA {0} key {1}\n'.format(mode, path))
                path = self.key_filenames.get(RSA).get(mode).get(PRIVATE)
                with open(path, 'xb') as fpub:
                    fpub.write(key.exportKey('PEM'))
                sys.stdout.write(' - Created new RSA {0} key {1}\n'.format(mode, path))
            except FileExistsError as e:
                raise DjangoCryptoFieldsError('RSA key already exists. Got {}'.format(str(e)))

    def create_aes(self, mode=None):
        """Creates AES keys and RSA encrypts them."""
        modes = [mode] if mode else self.key_filenames.get(AES)
        for mode in modes:
            with open(self.key_filenames.get(RSA).get(mode).get(PUBLIC), 'rb') as rsa_file:
                rsa_key = RSA_PUBLIC_KEY.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            aes_key = Random.new().read(16)
            key_file = self.key_filenames.get(AES).get(mode).get(PRIVATE)
            with open(key_file, 'xb') as faes:
                faes.write(rsa_key.encrypt(aes_key))
            sys.stdout.write(' - Created new AES {0} key {1}\n'.format(mode, key_file))

    def create_salt(self, mode=None):
        """Creates a salt and RSA encrypts it."""
        modes = [mode] if mode else self.key_filenames.get(SALT)
        for mode in modes:
            with open(self.key_filenames.get(RSA).get(mode).get(PUBLIC), 'rb') as rsa_file:
                rsa_key = RSA_PUBLIC_KEY.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            salt = Random.new().read(8)
            key_file = self.key_filenames.get(SALT).get(mode).get(PRIVATE)
            with open(key_file, 'xb') as fsalt:
                fsalt.write(rsa_key.encrypt(salt))
            sys.stdout.write(' - Created new salt {0} key {1}\n'.format(mode, key_file))
