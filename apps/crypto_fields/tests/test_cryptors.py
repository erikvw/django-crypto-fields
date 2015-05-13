from datetime import datetime

from django.test import TestCase

from ..classes import Cryptor
from ..exceptions import EncryptionError


class TestCryptors(TestCase):

    def test_encrypt_rsa(self):
        """Assert successful RSA roundtrip."""
        cryptor = Cryptor()
        plaintext = 'erik is a pleeb!!'
        for mode in cryptor.KEYS['rsa']:
            ciphertext = cryptor.rsa_encrypt(plaintext, mode)
            if mode != 'irreversible':
                self.assertEqual(plaintext, cryptor.rsa_decrypt(ciphertext, mode))

    def test_encrypt_rsa_irreversible(self):
        """Assert RSA irreversible cannot decrypt"""
        cryptor = Cryptor()
        plaintext = 'erik is a pleeb!!'
        ciphertext = cryptor.rsa_encrypt(plaintext, 'irreversible')
        self.assertRaises(AttributeError, cryptor.rsa_decrypt, ciphertext, 'irreversible')

    def test_encrypt_aes(self):
        """Assert successful AES roundtrip."""
        cryptor = Cryptor()
        plaintext = 'erik is a pleeb!!'
        for mode in cryptor.KEYS['aes']:
            ciphertext = cryptor.aes_encrypt(plaintext, mode)
            self.assertEqual(plaintext, cryptor.aes_decrypt(ciphertext, mode))

    def test_encrypt_rsa_length(self):
        """Assert RSA raises EncryptionError if plaintext is too long."""
        cryptor = Cryptor()
        for mode in cryptor.KEYS['rsa']:
            max_length = cryptor.rsa_key_info[mode]['max_message_length']
            plaintext = ''.join(['a' for i in range(0, max_length)])
            cryptor.rsa_encrypt(plaintext, mode)
            self.assertRaises(EncryptionError, cryptor.rsa_encrypt, plaintext + 'a', mode)

    def test_rsa_encoding(self):
        """Assert successful RSA roundtrip of byte return str."""
        cryptor = Cryptor()
        plaintext = 'erik is a pleeb!!∂ƒ˜∫˙ç'.encode('utf-8')
        ciphertext = cryptor.rsa_encrypt(plaintext, 'local')
        t2 = type(cryptor.rsa_decrypt(ciphertext, 'local'))
        self.assertTrue(type(t2), 'str')

    def test_rsa_type(self):
        """Assert fails for anything but str and byte."""
        cryptor = Cryptor()
        plaintext = 1
        self.assertRaises(EncryptionError, cryptor.rsa_encrypt, plaintext, 'local')
        plaintext = 1.0
        self.assertRaises(EncryptionError, cryptor.rsa_encrypt, plaintext, 'local')
        plaintext = datetime.today()
        self.assertRaises(EncryptionError, cryptor.rsa_encrypt, plaintext, 'local')

    def test_no_re_encrypt(self):
        """Assert raise error if attempting to encrypt a cipher."""
        cryptor = Cryptor()
        plaintext = 'erik is a pleeb!!'
        ciphertext1 = cryptor.rsa_encrypt(plaintext, 'local')
        self.assertRaises(EncryptionError, cryptor.rsa_encrypt, ciphertext1, 'local')
