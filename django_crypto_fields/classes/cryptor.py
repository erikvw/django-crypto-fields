import sys

from Crypto import Random
from Crypto.Cipher import AES as AES_CIPHER

from ..constants import RSA, AES, PRIVATE, PUBLIC, KEY_FILENAMES, ENCODING
from ..exceptions import EncryptionError

from .keys import KEYS


class Cryptor(object):
    """Base class for all classes providing RSA and AES encryption methods.

    The PEM file names and paths are in KEY_FILENAMES. KEYS is a copy of this except the
    filenames are replaced with the actual keys."""

    def __init__(self):
        pass

    def aes_encrypt(self, plaintext, mode):
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        aes_key = KEYS[AES][mode][PRIVATE]
        iv = Random.new().read(AES_CIPHER.block_size)
        cipher = AES_CIPHER.new(aes_key, AES_CIPHER.MODE_CFB, iv)
        return iv + cipher.encrypt(plaintext)

    def aes_decrypt(self, ciphertext, mode):
        aes_key = KEYS[AES][mode][PRIVATE]
        iv = ciphertext[:AES_CIPHER.block_size]
        cipher = AES_CIPHER.new(aes_key, AES_CIPHER.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)[AES_CIPHER.block_size:]
        return plaintext.decode(ENCODING)

    def rsa_encrypt(self, plaintext, mode):
        rsa_key = KEYS[RSA][mode][PUBLIC]
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
        rsa_key = KEYS[RSA][mode][PRIVATE]
        plaintext = rsa_key.decrypt(ciphertext)
        return plaintext.decode(ENCODING)

    def test_rsa(self):
        """ Tests keys roundtrip"""
        plaintext = 'erik is a pleeb!'
        for mode in KEY_FILENAMES[RSA]:
            try:
                rsa_key = KEYS[RSA][mode][PUBLIC]
                ciphertext = rsa_key.encrypt(plaintext.encode('utf_8'))
                sys.stdout.write('(*) Passed encrypt: ' + KEY_FILENAMES[RSA][mode][PUBLIC])
            except (AttributeError, TypeError) as e:
                print('( ) Failed encrypt: {} public ({})'.format(mode, e))
            try:
                rsa_key = KEYS[RSA][mode][PRIVATE]
                assert plaintext == rsa_key.decrypt(ciphertext).decode(ENCODING)
                print('(*) Passed decrypt: ' + KEY_FILENAMES[RSA][mode][PRIVATE])
            except (AttributeError, TypeError) as e:
                print('( ) Failed decrypt: {} private ({})'.format(mode, e))

    def test_aes(self):
        """ Tests keys roundtrip"""
        plaintext = 'erik is a pleeb!'
        for mode in KEY_FILENAMES[AES]:
            ciphertext = self.aes_encrypt(plaintext, mode)
            assert plaintext != ciphertext
            print('(*) Passed encrypt: ' + KEY_FILENAMES[AES][mode][PRIVATE])
            assert plaintext == self.aes_decrypt(ciphertext, mode)
            print('(*) Passed decrypt: ' + KEY_FILENAMES[AES][mode][PRIVATE])
