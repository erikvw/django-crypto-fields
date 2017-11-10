import sys

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA as RSA_PUBLIC_KEY
from django_crypto_fields.constants import style

from .constants import RSA, AES, SALT, PRIVATE, PUBLIC, RSA_KEY_SIZE
from .key_path_handler import KeyPathHandler


class DjangoCryptoFieldsKeyError(Exception):
    pass


class DjangoCryptoFieldsKeyAlreadyExist(Exception):
    pass


class KeyCreator:

    key_path_handler_cls = KeyPathHandler

    def __init__(self, key_path=None, key_prefix=None):
        self.key_path_handler = self.key_path_handler_cls(
            key_path=key_path, key_prefix=key_prefix)
        self.key_path = self.key_path_handler.key_path
        self.key_filenames = self.key_path_handler.key_filenames

    def create_keys(self):
        """Generates RSA and AES keys as per `key_filenames`.
        """
        if self.key_path_handler.key_files_exist:
            raise DjangoCryptoFieldsKeyAlreadyExist(
                f'Not creating new keys. Encryption keys already exist. See {self.key_path}.')
        sys.stdout.write(style.NOTICE('Generating new keys ...\n'))
        self._create_rsa()
        self._create_aes()
        self._create_salt()
        sys.stdout.write(style.SUCCESS('Done.\n'))

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
                sys.stdout.write(
                    ' - Created new RSA {0} key {1}\n'.format(mode, path))
                path = self.key_filenames.get(RSA).get(mode).get(PRIVATE)
                with open(path, 'xb') as fpub:
                    fpub.write(key.exportKey('PEM'))
                sys.stdout.write(
                    ' - Created new RSA {0} key {1}\n'.format(mode, path))
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
            sys.stdout.write(
                ' - Created new AES {0} key {1}\n'.format(mode, key_file))

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
            sys.stdout.write(
                ' - Created new salt {0} key {1}\n'.format(mode, key_file))
