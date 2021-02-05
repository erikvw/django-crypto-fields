from datetime import datetime

from django.apps import apps as django_apps
from django.test import TestCase, tag  # noqa

from ..constants import AES, LOCAL_MODE, RESTRICTED_MODE, RSA
from ..cryptor import Cryptor
from ..exceptions import EncryptionError


class TestCryptor(TestCase):
    def setUp(self):
        app_config = django_apps.get_app_config("django_crypto_fields")
        self.keys = app_config.encryption_keys

    def test_mode_support(self):
        self.assertEqual(self.keys.rsa_modes_supported, [LOCAL_MODE, RESTRICTED_MODE])
        self.assertEqual(self.keys.aes_modes_supported, [LOCAL_MODE, RESTRICTED_MODE])

    def test_encrypt_rsa(self):
        """Assert successful RSA roundtrip.
        """
        cryptor = Cryptor()
        plaintext = "erik is a pleeb!!"
        for mode in self.keys.rsa_modes_supported:
            ciphertext = cryptor.rsa_encrypt(plaintext, mode)
            self.assertEqual(plaintext, cryptor.rsa_decrypt(ciphertext, mode))

    def test_encrypt_aes(self):
        """Assert successful AES roundtrip.
        """
        cryptor = Cryptor()
        plaintext = "erik is a pleeb!!"
        for mode in self.keys.aes_modes_supported:
            ciphertext = cryptor.aes_encrypt(plaintext, mode)
            self.assertEqual(plaintext, cryptor.aes_decrypt(ciphertext, mode))

    def test_encrypt_rsa_length(self):
        """Assert RSA raises EncryptionError if plaintext is too long.
        """
        cryptor = Cryptor()
        for mode in self.keys.rsa_modes_supported:
            max_length = self.keys.rsa_key_info[mode]["max_message_length"]
            plaintext = "".join(["a" for _ in range(0, max_length)])
            cryptor.rsa_encrypt(plaintext, mode)
            self.assertRaises(
                EncryptionError, cryptor.rsa_encrypt, plaintext + "a", mode
            )

    def test_rsa_encoding(self):
        """Assert successful RSA roundtrip of byte return str.
        """
        cryptor = Cryptor()
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç".encode("utf-8")
        ciphertext = cryptor.rsa_encrypt(plaintext, LOCAL_MODE)
        t2 = type(cryptor.rsa_decrypt(ciphertext, LOCAL_MODE))
        self.assertTrue(type(t2), "str")

    def test_rsa_type(self):
        """Assert fails for anything but str and byte.
        """
        cryptor = Cryptor()
        plaintext = 1
        self.assertRaises(EncryptionError, cryptor.rsa_encrypt, plaintext, LOCAL_MODE)
        plaintext = 1.0
        self.assertRaises(EncryptionError, cryptor.rsa_encrypt, plaintext, LOCAL_MODE)
        plaintext = datetime.today()
        self.assertRaises(EncryptionError, cryptor.rsa_encrypt, plaintext, LOCAL_MODE)

    def test_no_re_encrypt(self):
        """Assert raise error if attempting to encrypt a cipher.
        """
        cryptor = Cryptor()
        plaintext = "erik is a pleeb!!"
        ciphertext1 = cryptor.rsa_encrypt(plaintext, LOCAL_MODE)
        self.assertRaises(EncryptionError, cryptor.rsa_encrypt, ciphertext1, LOCAL_MODE)

    def test_rsa_roundtrip(self):
        cryptor = Cryptor()
        plaintext = (
            "erik is a pleeb! ERIK IS A PLEEB 0123456789!@#$%^&*()"
            "_-+={[}]|\"':;>.<,?/~`±§"
        )
        for mode in cryptor.keys.key_filenames.get(RSA):
            try:
                ciphertext = cryptor.rsa_encrypt(plaintext, mode)
            except (AttributeError, TypeError) as e:
                self.fail(f"Failed encrypt: {mode} public ({e})\n")
            self.assertTrue(plaintext == cryptor.rsa_decrypt(ciphertext, mode))

    def test_aes_roundtrip(self):
        cryptor = Cryptor()
        plaintext = (
            "erik is a pleeb!\nERIK IS A PLEEB\n0123456789!@#$%^&*()_"
            "-+={[}]|\"':;>.<,?/~`±§\n"
        )
        for mode in cryptor.keys.key_filenames[AES]:
            ciphertext = cryptor.aes_encrypt(plaintext, mode)
            self.assertTrue(plaintext != ciphertext)
            self.assertTrue(plaintext == cryptor.aes_decrypt(ciphertext, mode))
