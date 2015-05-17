from datetime import datetime

from django.db import transaction
from django.test import TestCase
from django.db.utils import IntegrityError

from ..classes import Cryptor, FieldCryptor
from ..constants import HASH_PREFIX, CIPHER_PREFIX, ENCODING, KEY_FILENAMES
from ..exceptions import EncryptionError, MalformedCiphertextError

from .models import TestModel


class TestCryptors(TestCase):

    def test_encrypt_rsa(self):
        """Assert successful RSA roundtrip."""
        cryptor = Cryptor()
        plaintext = 'erik is a pleeb!!'
        for mode in cryptor.KEYS['rsa']:
            ciphertext = cryptor.rsa_encrypt(plaintext, mode)
            self.assertEqual(plaintext, cryptor.rsa_decrypt(ciphertext, mode))

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

    def test_is_encrypted_prefix(self):
        """Assert that just the HASH_PREFIX is a malformed ciphertext."""
        field_cryptor = FieldCryptor('rsa', 'local')
        value = HASH_PREFIX
        self.assertRaises(MalformedCiphertextError, field_cryptor.is_encrypted, value)
        value = HASH_PREFIX.encode(ENCODING)
        self.assertRaises(MalformedCiphertextError, field_cryptor.is_encrypted, value)
        value = CIPHER_PREFIX
        self.assertRaises(MalformedCiphertextError, field_cryptor.is_encrypted, value)
        value = CIPHER_PREFIX.encode(ENCODING)
        self.assertRaises(MalformedCiphertextError, field_cryptor.is_encrypted, value)

    def test_is_encrypted_format(self):
        """Assert malformed encrypted values raise exceptions."""
        field_cryptor = FieldCryptor('rsa', 'local')
        value = HASH_PREFIX + 'erik'
        self.assertRaises(MalformedCiphertextError, field_cryptor.is_encrypted, value)
        value = HASH_PREFIX.encode(ENCODING) + field_cryptor.hash('erik') + CIPHER_PREFIX.encode(ENCODING)
        self.assertRaises(MalformedCiphertextError, field_cryptor.is_encrypted, value)

    def test_is_encrypted(self):
        """Assert valid encrypted values are correctly interpreted as encrypted."""
        field_cryptor = FieldCryptor('rsa', 'local')
        value = HASH_PREFIX.encode(ENCODING) + field_cryptor.hash('erik')
        self.assertTrue(field_cryptor.is_encrypted(value, has_secret=False))
        value = (HASH_PREFIX.encode(ENCODING) + field_cryptor.hash('erik') +
                 CIPHER_PREFIX.encode(ENCODING) + field_cryptor.encrypt('erik'))
        self.assertTrue(field_cryptor.is_encrypted(value))
        value = 'erik'
        self.assertFalse(field_cryptor.is_encrypted(value))

    def test_is_not_encrypted(self):
        """Assert plaintext value is correctly interpreted as not encrypted."""
        field_cryptor = FieldCryptor('rsa', 'local')
        value = 'erik'
        self.assertFalse(field_cryptor.is_encrypted(value))

    def test_rsa_field_encryption(self):
        """Assert successful RSA field roundtrip."""
        plaintext = 'erik is a pleeb!!'
        for mode in KEY_FILENAMES['rsa']:
            field_cryptor = FieldCryptor('rsa', mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_aes_field_encryption(self):
        """Assert successful RSA field roundtrip."""
        plaintext = 'erik is a pleeb!!'
        for mode in KEY_FILENAMES['aes']:
            field_cryptor = FieldCryptor('aes', mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_rsa_field_encryption_encoded(self):
        """Assert successful RSA field roundtrip."""
        plaintext = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        for mode in KEY_FILENAMES['rsa']:
            field_cryptor = FieldCryptor('rsa', mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_aes_field_encryption_encoded(self):
        """Assert successful AES field roundtrip."""
        plaintext = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        for mode in KEY_FILENAMES['aes']:
            field_cryptor = FieldCryptor('aes', mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_rsa_field_encryption_update_secret(self):
        """Assert successful AES field roundtrip for same value."""
        plaintext = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        for mode in KEY_FILENAMES['rsa']:
            field_cryptor = FieldCryptor('rsa', mode)
            ciphertext1 = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext1))
            ciphertext2 = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext2))
            self.assertFalse(ciphertext1 == ciphertext2)

    def test_aes_field_encryption_update_secret(self):
        """Assert successful AES field roundtrip for same value."""
        plaintext = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        for mode in KEY_FILENAMES['aes']:
            field_cryptor = FieldCryptor('aes', mode)
            ciphertext1 = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext1))
            ciphertext2 = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext2))
            self.assertFalse(ciphertext1 == ciphertext2)

    def test_rsa_update_cipher_model(self):
        """Asserts plaintext can be encrypted, saved to model, retrieved by hash, and decrypted."""
        plaintext = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        cryptor = Cryptor()
        field_cryptor = FieldCryptor('rsa', 'local')
        hashed_value = field_cryptor.hash(plaintext)
        ciphertext1 = field_cryptor.encrypt(plaintext, update=False)
        field_cryptor.update_cipher_model(ciphertext1)
        secret = field_cryptor.cipher_model.objects.get(hash=hashed_value).secret
        field_cryptor.fetch_secret(HASH_PREFIX.encode(ENCODING) + hashed_value)
        self.assertEquals(plaintext, cryptor.rsa_decrypt(secret, 'local'))

    def test_aes_update_cipher_model(self):
        """Asserts plaintext can be encrypted, saved to model, retrieved by hash, and decrypted."""
        plaintext = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        cryptor = Cryptor()
        field_cryptor = FieldCryptor('aes', 'local')
        hashed_value = field_cryptor.hash(plaintext)
        ciphertext1 = field_cryptor.encrypt(plaintext, update=False)
        field_cryptor.update_cipher_model(ciphertext1)
        secret = field_cryptor.cipher_model.objects.get(hash=hashed_value).secret
        field_cryptor.fetch_secret(HASH_PREFIX.encode(ENCODING) + hashed_value)
        self.assertEquals(plaintext, cryptor.aes_decrypt(secret, 'local'))

    def test_get_secret(self):
        """Asserts secret is returned either as None or the secret."""
        cryptor = Cryptor()
        field_cryptor = FieldCryptor('rsa', 'local')
        plaintext = None
        ciphertext = field_cryptor.encrypt(plaintext)
        secret = field_cryptor.get_secret(ciphertext)
        self.assertIsNone(secret)
        plaintext = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        ciphertext = field_cryptor.encrypt(plaintext)
        secret = field_cryptor.get_secret(ciphertext)
        self.assertEquals(plaintext, cryptor.rsa_decrypt(secret, 'local'))

    def test_rsa_field_as_none(self):
        """Asserts RSA roundtrip on None."""
        field_cryptor = FieldCryptor('rsa', 'local')
        plaintext = None
        ciphertext = field_cryptor.encrypt(plaintext)
        self.assertIsNone(field_cryptor.decrypt(ciphertext))

    def test_aes_field_as_none(self):
        """Asserts AES roundtrip on None."""
        field_cryptor = FieldCryptor('aes', 'local')
        plaintext = None
        ciphertext = field_cryptor.encrypt(plaintext)
        self.assertIsNone(field_cryptor.decrypt(ciphertext))

    def test_model_with_encrypted_fields(self):
        """Asserts roundtrip via a model with encrypted fields."""
        first_name = 'erik'
        identity = '123456789'
        comment = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        test_model = TestModel.objects.create(
            first_name=first_name,
            identity=identity,
            comment=comment)
        self.assertEqual(test_model.first_name, first_name)
        self.assertEqual(test_model.identity, identity)
        self.assertEqual(test_model.comment, comment)
        test_model = TestModel.objects.get(identity=identity)
        self.assertEqual(test_model.first_name, first_name)
        self.assertEqual(test_model.identity, identity)
        self.assertEqual(test_model.comment, comment)

    def test_model_with_unique_field(self):
        """Asserts unique constraint works on an encrypted field.

        identity = EncryptedTextField(
            verbose_name="Identity",
            unique=True)
        """
        first_name = 'erik'
        identity = '123456789'
        comment = 'erik is a pleeb!!∂ƒ˜∫˙ç'
        TestModel.objects.create(
            first_name=first_name,
            identity=identity,
            comment=comment)
        first_name2 = 'erik2'
        comment2 = 'erik was a pleeb!!∂ƒ˜∫˙ç'
        with transaction.atomic():
            self.assertRaises(
                IntegrityError,
                TestModel.objects.create,
                first_name=first_name2,
                identity=identity,
                comment=comment2)
        test_model = TestModel.objects.get(identity=identity)
        self.assertEqual(test_model.first_name, first_name)
        self.assertEqual(test_model.identity, identity)
        self.assertEqual(test_model.comment, comment)
