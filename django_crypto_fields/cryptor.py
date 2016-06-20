import sys

from Crypto import Random
from Crypto.Cipher import AES as AES_CIPHER

from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import AppRegistryNotReady

from .constants import RSA, AES, PRIVATE, PUBLIC, ENCODING, style
from .exceptions import EncryptionError


class Cryptor(object):
    """Base class for all classes providing RSA and AES encryption methods.

    The PEM file names and paths are in KEY_FILENAMES. KEYS is a copy of this except the
    filenames are replaced with the actual keys."""

    def __init__(self, keys=None):
        try:
            # do not use MODE_CFB, see comments in pycrypto.blockalgo.py
            self.AES_ENCRYPTION_MODE = settings.AES_ENCRYPTION_MODE
        except AttributeError:
            self.AES_ENCRYPTION_MODE = AES_CIPHER.MODE_CBC
        try:
            # ignore "keys" parameter if Django is loaded
            self.keys = django_apps.get_app_config('django_crypto_fields').encryption_keys
        except AppRegistryNotReady:
            self.keys = keys

    def padded(self, plaintext, block_size):
        """Return string padded so length is a multiple of the block size.
            * store length of padding in last two characters of plaintext.
            * if padding is 0, pad as if padding is 16.
            * AES_CIPHER.MODE_CFB should not be used, but was used without padding
              in the past. Continue to skip padding for this mode.
        """
        if self.AES_ENCRYPTION_MODE == AES_CIPHER.MODE_CFB:
            padding_length = 0
        else:
            padding_length = (block_size - len(plaintext) % block_size) % block_size
            padding_length = padding_length or 16
        return plaintext + b'\x00' * (padding_length - 2) + str(padding_length.zfill(2)).encode()

    def unpadded(self, plaintext, block_size):
        """Return original plaintext without padding.

        Length of padding is stored in last two characters of plaintext."""
        if self.AES_ENCRYPTION_MODE == AES_CIPHER.MODE_CFB:
            return plaintext
        return plaintext[:-int(plaintext[-2:])]

    def aes_encrypt(self, plaintext, mode):
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        attr = '_'.join([AES, mode, PRIVATE, 'key'])
        aes_key = getattr(self.keys, attr)
        iv = Random.new().read(AES_CIPHER.block_size)
        cipher = AES_CIPHER.new(aes_key, self.AES_ENCRYPTION_MODE, iv)
        padded_plaintext = self.padded(plaintext, cipher.block_size)
        return iv + cipher.encrypt(padded_plaintext)

    def aes_decrypt(self, ciphertext, mode):
        attr = '_'.join([AES, mode, PRIVATE, 'key'])
        aes_key = getattr(self.keys, attr)
        iv = ciphertext[:AES_CIPHER.block_size]
        cipher = AES_CIPHER.new(aes_key, self.AES_ENCRYPTION_MODE, iv)
        plaintext = cipher.decrypt(ciphertext)[AES_CIPHER.block_size:]
        return self.unpadded(plaintext.decode(ENCODING), cipher.block_size)

    def rsa_encrypt(self, plaintext, mode):
        attr = '_'.join([RSA, mode, PUBLIC, 'key'])
        rsa_key = getattr(self.keys, attr)
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        try:
            ciphertext = rsa_key.encrypt(plaintext)
        except (ValueError, TypeError) as e:
            raise EncryptionError('RSA encryption failed for value. Got \'{}\''.format(e))
        return ciphertext

    def rsa_decrypt(self, ciphertext, mode):
        attr = '_'.join([RSA, mode, PRIVATE, 'key'])
        rsa_key = getattr(self.keys, attr)
        plaintext = rsa_key.decrypt(ciphertext)
        return plaintext.decode(ENCODING)

    def test_rsa(self):
        """ Tests keys roundtrip"""
        plaintext = 'erik is a pleeb! ERIK IS A PLEEB 0123456789!@#$%^&*()_-+={[}]|\"\':;>.<,?/~`±§'
        for mode in self.keys.key_filenames.get(RSA):
            try:
                ciphertext = self.rsa_encrypt(plaintext, mode)
                sys.stdout.write(style.SUCCESS('(*) Passed encrypt: {}\n'.format(
                    self.keys.key_filenames[RSA][mode][PUBLIC])))
            except (AttributeError, TypeError) as e:
                sys.stdout.write(style.ERROR('( ) Failed encrypt: {} public ({})\n'.format(mode, e)))
            try:
                assert plaintext == self.rsa_decrypt(ciphertext, mode)
                sys.stdout.write(style.SUCCESS('(*) Passed decrypt: {}\n'.format(
                    self.keys.key_filenames[RSA][mode][PRIVATE])))
            except (AttributeError, TypeError) as e:
                sys.stdout.write(style.ERROR('( ) Failed decrypt: {} private ({})\n'.format(mode, e)))

    def test_aes(self):
        """ Tests keys roundtrip"""
        plaintext = 'erik is a pleeb!\nERIK IS A PLEEB\n0123456789!@#$%^&*()_-+={[}]|\"\':;>.<,?/~`±§\n'
        for mode in self.keys.key_filenames[AES]:
            ciphertext = self.aes_encrypt(plaintext, mode)
            assert plaintext != ciphertext
            sys.stdout.write(style.SUCCESS('(*) Passed encrypt: {}\n'.format(
                self.keys.key_filenames[AES][mode][PRIVATE])))
            assert plaintext == self.aes_decrypt(ciphertext, mode)
            sys.stdout.write(style.SUCCESS('(*) Passed decrypt: {}\n'.format(
                self.keys.key_filenames[AES][mode][PRIVATE])))
