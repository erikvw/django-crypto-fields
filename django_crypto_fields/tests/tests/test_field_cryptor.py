from datetime import date

from django.db import transaction
from django.db.utils import IntegrityError
from django.test import TestCase, tag

from django_crypto_fields.cipher import CipherParser
from django_crypto_fields.constants import AES, HASH_PREFIX, LOCAL_MODE, RSA
from django_crypto_fields.cryptor import Cryptor
from django_crypto_fields.exceptions import (
    DjangoCryptoFieldsError,
    MalformedCiphertextError,
)
from django_crypto_fields.field_cryptor import FieldCryptor
from django_crypto_fields.keys import encryption_keys
from django_crypto_fields.utils import get_crypt_model_cls

from ...encoding import safe_encode
from ..models import TestModel


class TestFieldCryptor(TestCase):
    def setUp(self):
        encryption_keys.reset_and_delete_keys(verbose=False)
        encryption_keys.verbose = False
        encryption_keys.initialize()

    def tearDown(self):
        encryption_keys.reset_and_delete_keys(verbose=False)

    def test_verify_hashed_value(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = field_cryptor.encrypt("Mohammed Ali floats like a butterfly")
        p = CipherParser(value, field_cryptor.salt_key)
        try:
            p.validate_hashed_value()
        except MalformedCiphertextError:
            self.fail("MalformedCiphertextError unexpectedly raised")

    def test_verify_is_encrypted(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = HASH_PREFIX.encode() + field_cryptor.hash(
            "Mohammed Ali floats like a butterfly"
        )
        self.assertTrue(field_cryptor.is_encrypted(value))

    def test_verify_is_not_encrypted(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = "Mohammed Ali floats like a butterfly"
        self.assertFalse(field_cryptor.is_encrypted(value))
        value = b"Mohammed Ali floats like a butterfly"
        self.assertFalse(field_cryptor.is_encrypted(value))

    def test_verify_value(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        cipher = field_cryptor.encrypt("Mohammed Ali floats like a butterfly")
        p = CipherParser(cipher)
        self.assertIsNotNone(p.secret)

    def test_rsa_field_encryption(self):
        """Assert successful RSA field roundtrip."""
        plaintext = "erik is a pleeb!!"
        for mode in encryption_keys.get(RSA):
            field_cryptor = FieldCryptor(RSA, mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_rsa_field_encryption_update_secret(self):
        """Assert successful RSA field roundtrip for same value."""
        value = "erik is a pleeb!!∂ƒ˜∫˙ç"
        for mode in encryption_keys.get(RSA):
            field_cryptor = FieldCryptor(RSA, mode)
            cipher1 = field_cryptor.encrypt(value)
            self.assertEqual(value, field_cryptor.decrypt(cipher1))
            cipher2 = field_cryptor.encrypt(value)
            self.assertEqual(value, field_cryptor.decrypt(cipher2))
            self.assertFalse(cipher1 == cipher2)

    def test_aes_field_encryption(self):
        """Assert successful RSA field roundtrip."""
        value = "erik is a pleeb!!"
        for mode in encryption_keys.get(AES):
            field_cryptor = FieldCryptor(AES, mode)
            ciphertext = field_cryptor.encrypt(value)
            self.assertEqual(value, field_cryptor.decrypt(ciphertext))

    def test_rsa_field_encryption_encoded(self):
        """Assert successful RSA field roundtrip."""
        value = "erik is a pleeb!!∂ƒ˜∫˙ç"
        for mode in encryption_keys.get(RSA):
            field_cryptor = FieldCryptor(RSA, mode)
            ciphertext = field_cryptor.encrypt(value)
            self.assertEqual(value, field_cryptor.decrypt(ciphertext))

    def test_aes_field_encryption_encoded(self):
        """Assert successful AES field roundtrip."""
        value = "erik is a pleeb!!∂ƒ˜∫˙ç"
        for mode in encryption_keys.get(AES):
            field_cryptor = FieldCryptor(AES, mode)
            ciphertext = field_cryptor.encrypt(value)
            self.assertEqual(value, field_cryptor.decrypt(ciphertext))

    def test_aes_field_encryption_update_secret(self):
        """Assert successful AES field roundtrip for same value."""
        value = "erik is a pleeb!!∂ƒ˜∫˙ç"
        for mode in encryption_keys.get(AES):
            field_cryptor = FieldCryptor(AES, mode)
            ciphertext1 = field_cryptor.encrypt(value)
            self.assertEqual(value, field_cryptor.decrypt(ciphertext1))
            ciphertext2 = field_cryptor.encrypt(value)
            self.assertEqual(value, field_cryptor.decrypt(ciphertext2))
            self.assertFalse(ciphertext1 == ciphertext2)

    def test_rsa_update_crypt_model(self):
        """Asserts plaintext can be encrypted, saved to model,
        retrieved by hash, and decrypted.
        """
        value = "erik is a pleeb!!∂ƒ˜∫˙ç"
        cryptor = Cryptor(algorithm=RSA, access_mode=LOCAL_MODE)
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        hashed_value = field_cryptor.hash(value)
        field_cryptor.encrypt(value, update=True)
        secret = get_crypt_model_cls().objects.get(hash=hashed_value.decode()).secret
        field_cryptor.fetch_secret(HASH_PREFIX.encode() + hashed_value)
        self.assertEqual(value, cryptor.decrypt(secret))

    def test_aes_update_crypt_model(self):
        """Asserts plaintext can be encrypted, saved to model,
        retrieved by hash, and decrypted.
        """
        value = "erik is a pleeb!!∂ƒ˜∫˙ç"
        field_cryptor = FieldCryptor(AES, LOCAL_MODE)
        field_cryptor.encrypt(value, update=True)
        hashed_value = field_cryptor.hash(value)
        secret = get_crypt_model_cls().objects.get(hash=hashed_value.decode()).secret
        field_cryptor.fetch_secret(HASH_PREFIX.encode() + hashed_value)
        self.assertEqual(value, field_cryptor.cryptor.decrypt(secret))

    def test_none_value_is_not_added_to_crypt_model(self):
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 0)
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = None
        cipher = field_cryptor.encrypt(value, update=True)
        p = CipherParser(cipher)
        self.assertIsNone(p.secret)
        self.assertIsNone(p.hash_prefix)
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 0)

    def test_empty_value_is_added_once_to_crypt_model(self):
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 0)
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = ""
        cipher = field_cryptor.encrypt(value, update=True)
        p = CipherParser(cipher)
        self.assertIsNotNone(p.secret)
        self.assertIsNotNone(p.hash_prefix)
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 1)
        field_cryptor.encrypt(value, update=True)
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 1)

    def test_get_secret(self):
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 0)
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = "erik is a pleeb!!∂ƒ˜∫˙ç"
        cipher = field_cryptor.encrypt(value, update=True)
        p = CipherParser(cipher)
        self.assertIsNotNone(p.secret)
        self.assertEqual(value, field_cryptor.decrypt(p.hash_prefix + p.hashed_value))
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 1)

    def test_rsa_field_as_none_raises(self):
        """Asserts RSA cannot roundtrip on None."""
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = None
        cipher = field_cryptor.encrypt(value)
        self.assertRaises(DjangoCryptoFieldsError, field_cryptor.decrypt, cipher)

    def test_aes_field_as_none_raises(self):
        """Asserts AES cannot roundtrip on None."""
        field_cryptor = FieldCryptor(AES, LOCAL_MODE)
        value = None
        cipher = field_cryptor.encrypt(value)
        self.assertRaises(DjangoCryptoFieldsError, field_cryptor.decrypt, cipher)

    def test_rsa_field_with_empty_string(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = ""
        cipher = field_cryptor.encrypt(value)
        self.assertEqual(value, field_cryptor.decrypt(cipher))

    def test_aes_field_with_empty_string(self):
        field_cryptor = FieldCryptor(AES, LOCAL_MODE)
        value = ""
        cipher = field_cryptor.encrypt(value)
        self.assertEqual(value, field_cryptor.decrypt(cipher))

    def test_rsa_field_with_zero(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = safe_encode(0).decode()
        cipher = field_cryptor.encrypt(value)
        self.assertEqual(value, field_cryptor.decrypt(cipher))

    def test_aes_field_with_zero(self):
        field_cryptor = FieldCryptor(AES, LOCAL_MODE)
        value = safe_encode(0).decode()
        cipher = field_cryptor.encrypt(value)
        self.assertEqual(value, field_cryptor.decrypt(cipher))

    def test_rsa_field_with_date(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = safe_encode(date.today()).decode()
        cipher = field_cryptor.encrypt(value)
        self.assertEqual(value, field_cryptor.decrypt(cipher))

    def test_aes_field_with_date(self):
        field_cryptor = FieldCryptor(AES, LOCAL_MODE)
        value = safe_encode(date.today()).decode()
        cipher = field_cryptor.encrypt(value)
        self.assertEqual(value, field_cryptor.decrypt(cipher))

    @tag("6")
    def test_model_with_encrypted_fields(self):
        """Asserts roundtrip via a model with encrypted fields."""
        data = dict(
            firstname="erik",
            identity="123456789",
            comment="erik is a pleeb!!∂ƒ˜∫˙ç",
        )
        TestModel.objects.create(**data)
        for attr, value in data.items():
            with self.subTest(attr=attr, value=value):
                test_model = TestModel.objects.get(**{attr: value})
                for attr1, value1 in data.items():
                    self.assertEqual(getattr(test_model, attr1), value1)
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 3)

    def test_model_with_encrypted_fields_empty_string(self):
        """Asserts roundtrip via a model with encrypted fields.

        Note: firstname is None and comment is an empty string
          Expect identity and comment to be added to Crypt
        """
        data = dict(firstname=None, identity="123456789", comment="")
        TestModel.objects.create(**data)
        for attr, value in data.items():
            with self.subTest(attr=attr, value=value):
                test_model = TestModel.objects.get(**{attr: value})
                for attr1, value1 in data.items():
                    self.assertEqual(getattr(test_model, attr1), value1)
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 2)

    def test_model_with_encrypted_fields_as_none(self):
        """Asserts roundtrip via a model with encrypted fields.

        Note: comment is None
        """
        firstname = "erik"
        identity = "123456789"
        comment = None
        test_model = TestModel.objects.create(
            firstname=firstname, identity=identity, comment=comment
        )
        self.assertEqual(test_model.firstname, firstname)
        self.assertEqual(test_model.identity, identity)
        self.assertEqual(test_model.comment, comment)
        test_model = TestModel.objects.get(identity=identity)
        self.assertEqual(test_model.firstname, firstname)
        self.assertEqual(test_model.identity, identity)
        self.assertEqual(test_model.comment, comment)
        self.assertEqual(get_crypt_model_cls().objects.all().count(), 2)

    def test_model_with_unique_field(self):
        """Asserts unique constraint works on an encrypted field.

        identity = EncryptedTextField(
            verbose_name="Identity",
            unique=True)
        """
        firstname = "erik"
        identity = "123456789"
        comment = "erik is a pleeb!!∂ƒ˜∫˙ç"
        TestModel.objects.create(firstname=firstname, identity=identity, comment=comment)
        firstname2 = "erik2"
        comment2 = "erik was a pleeb!!∂ƒ˜∫˙ç"
        with transaction.atomic():
            self.assertRaises(
                IntegrityError,
                TestModel.objects.create,
                firstname=firstname2,
                identity=identity,
                comment=comment2,
            )
        test_model = TestModel.objects.get(identity=identity)
        self.assertEqual(test_model.firstname, firstname)
        self.assertEqual(test_model.identity, identity)
        self.assertEqual(test_model.comment, comment)
