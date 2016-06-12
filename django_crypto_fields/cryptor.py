import sys

from Crypto import Random
from Crypto.Cipher import AES as AES_CIPHER

from django.apps import apps as django_apps
from django.core.exceptions import AppRegistryNotReady

from .constants import RSA, AES, PRIVATE, PUBLIC, ENCODING, style
from .exceptions import EncryptionError


class Cryptor(object):
    """Base class for all classes providing RSA and AES encryption methods.

    The PEM file names and paths are in KEY_FILENAMES. KEYS is a copy of this except the
    filenames are replaced with the actual keys."""

    def __init__(self, keys=None):
        try:
            # ignore "keys" parameter if Django is loaded
            self.keys = django_apps.get_app_config('django_crypto_fields').encryption_keys
        except AppRegistryNotReady:
            self.keys = keys

    def aes_encrypt(self, plaintext, mode):
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        attr = '_'.join([AES, mode, PRIVATE, 'key'])
        aes_key = getattr(self.keys, attr)
        iv = Random.new().read(AES_CIPHER.block_size)
        cipher = AES_CIPHER.new(aes_key, AES_CIPHER.MODE_CFB, iv)
        return iv + cipher.encrypt(plaintext)

    def aes_decrypt(self, ciphertext, mode):
        attr = '_'.join([AES, mode, PRIVATE, 'key'])
        aes_key = getattr(self.keys, attr)
        iv = ciphertext[:AES_CIPHER.block_size]
        cipher = AES_CIPHER.new(aes_key, AES_CIPHER.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)[AES_CIPHER.block_size:]
        return plaintext.decode(ENCODING)

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
