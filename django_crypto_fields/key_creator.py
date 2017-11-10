import sys

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA as RSA_PUBLIC_KEY
from django.conf import settings

from .constants import style, RSA, AES, SALT, PRIVATE, PUBLIC, RSA_KEY_SIZE
from .key_files import KeyFiles

try:
    verbose_mode = settings.VERBOSE_MODE
except AttributeError:
    verbose_mode = True


class DjangoCryptoFieldsKeyError(Exception):
    pass


class DjangoCryptoFieldsKeyAlreadyExist(Exception):
    pass


class KeyCreator:

    """Creates new keys if key do not yet exist.
    """

    key_files_cls = KeyFiles

    def __init__(self, **kwargs):
        self.verbose = verbose_mode
        self.key_files = self.key_files_cls(**kwargs)
        self.key_path = self.key_files.key_path
        self.key_filenames = self.key_files.key_filenames
        self.temp_path = self.key_files.temp_path

    def create_keys(self):
        """Generates RSA and AES keys as per `key_filenames`.
        """
        if self.key_files.key_files_exist:
            raise DjangoCryptoFieldsKeyAlreadyExist(
                f'Not creating new keys. Encryption keys already exist. See {self.key_path}.')
        sys.stdout.write(style.WARNING(
            '  * Generating new encryption keys ...\n'))
        self._create_rsa()
        self._create_aes()
        self._create_salt()
        sys.stdout.write('    Done generating new encryption keys.\n')
        sys.stdout.write(
            f'    Your new encryption keys are in {self.key_path}.\n')
        sys.stdout.write(style.ERROR(
            f'    DON\'T FORGET TO BACKUP YOUR NEW KEYS!!\n'))

    def _create_rsa(self, mode=None):
        """Creates RSA keys.
        """
        modes = [mode] if mode else self.key_filenames.get(RSA)
        for mode in modes:
            key = RSA_PUBLIC_KEY.generate(RSA_KEY_SIZE)
            pub = key.publickey()
            path = self.key_filenames.get(RSA).get(mode).get(PUBLIC)
            try:
                with open(path, 'xb') as fpub:
                    fpub.write(pub.exportKey('PEM'))
                if self.verbose:
                    sys.stdout.write(f' - Created new RSA {mode} key {path}\n')
                path = self.key_filenames.get(RSA).get(mode).get(PRIVATE)
                with open(path, 'xb') as fpub:
                    fpub.write(key.exportKey('PEM'))
                if self.verbose:
                    sys.stdout.write(f' - Created new RSA {mode} key {path}\n')
            except FileExistsError as e:
                raise DjangoCryptoFieldsKeyError(
                    f'RSA key already exists. Got {e}')

    def _create_aes(self, mode=None):
        """Creates AES keys and RSA encrypts them.
        """
        modes = [mode] if mode else self.key_filenames.get(AES)
        for mode in modes:
            with open(self.key_filenames.get(RSA).get(mode).get(PUBLIC), 'rb') as rsa_file:
                rsa_key = RSA_PUBLIC_KEY.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            aes_key = Random.new().read(16)
            key_file = self.key_filenames.get(AES).get(mode).get(PRIVATE)
            with open(key_file, 'xb') as faes:
                faes.write(rsa_key.encrypt(aes_key))
            if self.verbose:
                sys.stdout.write(f' - Created new AES {mode} key {key_file}\n')

    def _create_salt(self, mode=None):
        """Creates a salt and RSA encrypts it.
        """
        modes = [mode] if mode else self.key_filenames.get(SALT)
        for mode in modes:
            with open(self.key_filenames.get(RSA).get(mode).get(PUBLIC), 'rb') as rsa_file:
                rsa_key = RSA_PUBLIC_KEY.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            salt = Random.new().read(8)
            key_file = self.key_filenames.get(SALT).get(mode).get(PRIVATE)
            with open(key_file, 'xb') as fsalt:
                fsalt.write(rsa_key.encrypt(salt))
            if self.verbose:
                sys.stdout.write(
                    f' - Created new salt {mode} key {key_file}\n')
