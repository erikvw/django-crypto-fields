from datetime import date, datetime

from django.test import TestCase, tag

from django_crypto_fields.constants import AES, LOCAL_MODE, RESTRICTED_MODE, RSA
from django_crypto_fields.cryptor import Cryptor
from django_crypto_fields.exceptions import (
    DjangoCryptoFieldsEncodingError,
    EncryptionError,
)
from django_crypto_fields.keys import encryption_keys


class TestCryptor(TestCase):
    def setUp(self):
        encryption_keys.reset_and_delete_keys(verbose=False)
        encryption_keys.verbose = False
        encryption_keys.initialize()

    def tearDown(self):
        encryption_keys.reset_and_delete_keys(verbose=False)

    def test_mode_support(self):
        self.assertEqual(encryption_keys.rsa_modes_supported, [LOCAL_MODE, RESTRICTED_MODE])
        self.assertEqual(encryption_keys.aes_modes_supported, [LOCAL_MODE, RESTRICTED_MODE])

    def test_encrypt_rsa(self):
        """Assert successful RSA roundtrip."""
        for mode in encryption_keys.rsa_modes_supported:
            cryptor = Cryptor(algorithm=RSA, access_mode=mode)
            plaintext = "erik is a pleeb!!"
            ciphertext = cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, cryptor.decrypt(ciphertext))

    def test_encrypt_aes(self):
        """Assert successful AES roundtrip."""
        for mode in encryption_keys.aes_modes_supported:
            cryptor = Cryptor(algorithm=AES, access_mode=mode)
            plaintext = "erik is a pleeb!!"
            ciphertext = cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, cryptor.decrypt(ciphertext))

    def test_encrypt_rsa_length(self):
        """Assert RSA raises EncryptionError if plaintext is too long."""
        for mode in encryption_keys.rsa_modes_supported:
            cryptor = Cryptor(algorithm=RSA, access_mode=mode)
            max_length = encryption_keys.rsa_key_info[mode]["max_message_length"]
            plaintext = "".join(["a" for _ in range(0, max_length)])
            cryptor.encrypt(plaintext)
            self.assertRaises(EncryptionError, cryptor.encrypt, plaintext + "a")

    @tag("1")
    def test_rsa_encoding(self):
        """Assert successful RSA roundtrip of byte return str."""
        cryptor = Cryptor(algorithm=RSA, access_mode=LOCAL_MODE)
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç"
        ciphertext = cryptor.encrypt(plaintext)
        t2 = type(cryptor.decrypt(ciphertext))
        self.assertTrue(type(t2), "str")

    def test_rsa_type(self):
        cryptor = Cryptor(algorithm=RSA, access_mode=LOCAL_MODE)
        for value in ["", 1, 1.0, date.today(), datetime.today()]:
            with self.subTest(value=value):
                try:
                    cryptor.encrypt(value)
                except EncryptionError as e:
                    self.fail(e)

    @tag("1")
    def test_no_re_encrypt(self):
        """Assert raise error if attempting to encrypt a cipher."""
        cryptor = Cryptor(algorithm=RSA, access_mode=LOCAL_MODE)
        plaintext = "erik is a pleeb!!"
        ciphertext1 = cryptor.encrypt(plaintext)
        self.assertRaises(DjangoCryptoFieldsEncodingError, cryptor.encrypt, ciphertext1)

    def test_rsa_roundtrip(self):
        plaintext = (
            "erik is a pleeb! ERIK IS A PLEEB 0123456789!@#$%^&*()" "_-+={[}]|\"':;>.<,?/~`±§"
        )
        for mode in encryption_keys.rsa_modes_supported:
            cryptor = Cryptor(algorithm=RSA, access_mode=mode)
            try:
                ciphertext = cryptor.encrypt(plaintext)
            except (AttributeError, TypeError) as e:
                self.fail(f"Failed encrypt: {mode} public ({e})\n")
            self.assertTrue(plaintext == cryptor.decrypt(ciphertext))

    def test_aes_roundtrip(self):
        plaintext = (
            "erik is a pleeb!\nERIK IS A PLEEB\n0123456789!@#$%^&*()_"
            "-+={[}]|\"':;>.<,?/~`±§\n"
        )
        for mode in encryption_keys.aes_modes_supported:
            cryptor = Cryptor(algorithm=AES, access_mode=mode)
            ciphertext = cryptor.encrypt(plaintext)
            self.assertTrue(plaintext != ciphertext)
            self.assertTrue(plaintext == cryptor.decrypt(ciphertext))
