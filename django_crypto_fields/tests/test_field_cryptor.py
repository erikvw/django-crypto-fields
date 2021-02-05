from django.apps import apps as django_apps
from django.db import transaction
from django.db.utils import IntegrityError
from django.test import TestCase, tag  # noqa

from ..constants import AES, ENCODING, HASH_PREFIX, LOCAL_MODE, RSA
from ..cryptor import Cryptor
from ..exceptions import MalformedCiphertextError
from ..field_cryptor import FieldCryptor
from .models import TestModel


class TestFieldCryptor(TestCase):
    def setUp(self):
        app_config = django_apps.get_app_config("django_crypto_fields")
        self.keys = app_config.encryption_keys

    def test_can_verify_hash_as_none(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = None
        self.assertRaises(TypeError, field_cryptor.verify_hash, value)
        value = ""
        self.assertRaises(MalformedCiphertextError, field_cryptor.verify_hash, value)
        value = b""
        self.assertRaises(MalformedCiphertextError, field_cryptor.verify_hash, value)

    def test_can_verify_hash_not_raises(self):
        """Assert does NOT raise on valid hash.
        """
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = HASH_PREFIX.encode(ENCODING) + field_cryptor.hash(
            "Mohammed Ali floats like a butterfly"
        )
        try:
            field_cryptor.verify_hash(value)
        except MalformedCiphertextError:
            self.fail("MalformedCiphertextError unexpectedly raised")
        else:
            pass

    def test_can_verify_hash_raises(self):
        """Assert does raises on invalid hash.
        """
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = "erik"  # missing prefix
        self.assertRaises(MalformedCiphertextError, field_cryptor.verify_hash, value)
        value = HASH_PREFIX + "blah"  # incorrect prefix
        self.assertRaises(MalformedCiphertextError, field_cryptor.verify_hash, value)
        value = HASH_PREFIX  # no hash following prefix
        self.assertRaises(MalformedCiphertextError, field_cryptor.verify_hash, value)

    def test_verify_with_secret(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = field_cryptor.encrypt("Mohammed Ali floats like a butterfly")
        self.assertTrue(field_cryptor.verify_secret(value))

    def test_raises_on_verify_without_secret(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = HASH_PREFIX.encode(ENCODING) + field_cryptor.hash(
            "Mohammed Ali floats like a butterfly"
        )
        self.assertRaises(MalformedCiphertextError, field_cryptor.verify_secret, value)

    def test_verify_is_encrypted(self):
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        value = HASH_PREFIX.encode(ENCODING) + field_cryptor.hash(
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
        value = "Mohammed Ali floats like a butterfly"
        self.assertRaises(MalformedCiphertextError, field_cryptor.verify_value, value)
        value = field_cryptor.encrypt("Mohammed Ali floats like a butterfly")
        self.assertEqual(value, field_cryptor.verify_value(value))

    def test_rsa_field_encryption(self):
        """Assert successful RSA field roundtrip.
        """
        plaintext = "erik is a pleeb!!"
        for mode in self.keys.key_filenames[RSA]:
            field_cryptor = FieldCryptor(RSA, mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_rsa_field_encryption_update_secret(self):
        """Assert successful AES field roundtrip for same value.
        """
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç"
        for mode in self.keys.key_filenames[RSA]:
            field_cryptor = FieldCryptor(RSA, mode)
            ciphertext1 = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext1))
            ciphertext2 = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext2))
            self.assertFalse(ciphertext1 == ciphertext2)

    def test_aes_field_encryption(self):
        """Assert successful RSA field roundtrip.
        """
        plaintext = "erik is a pleeb!!"
        for mode in self.keys.key_filenames[AES]:
            field_cryptor = FieldCryptor(AES, mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_rsa_field_encryption_encoded(self):
        """Assert successful RSA field roundtrip.
        """
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç"
        for mode in self.keys.key_filenames[RSA]:
            field_cryptor = FieldCryptor(RSA, mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_aes_field_encryption_encoded(self):
        """Assert successful AES field roundtrip.
        """
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç"
        for mode in self.keys.key_filenames[AES]:
            field_cryptor = FieldCryptor(AES, mode)
            ciphertext = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext))

    def test_aes_field_encryption_update_secret(self):
        """Assert successful AES field roundtrip for same value.
        """
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç"
        for mode in self.keys.key_filenames[AES]:
            field_cryptor = FieldCryptor(AES, mode)
            ciphertext1 = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext1))
            ciphertext2 = field_cryptor.encrypt(plaintext)
            self.assertEqual(plaintext, field_cryptor.decrypt(ciphertext2))
            self.assertFalse(ciphertext1 == ciphertext2)

    def test_rsa_update_crypt_model(self):
        """Asserts plaintext can be encrypted, saved to model,
        retrieved by hash, and decrypted.
        """
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç"
        cryptor = Cryptor()
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        hashed_value = field_cryptor.hash(plaintext)
        ciphertext1 = field_cryptor.encrypt(plaintext, update=False)
        field_cryptor.update_crypt(ciphertext1)
        secret = field_cryptor.crypt_model_cls.objects.get(hash=hashed_value).secret
        field_cryptor.fetch_secret(HASH_PREFIX.encode(ENCODING) + hashed_value)
        self.assertEqual(plaintext, cryptor.rsa_decrypt(secret, LOCAL_MODE))

    def test_aes_update_crypt_model(self):
        """Asserts plaintext can be encrypted, saved to model,
        retrieved by hash, and decrypted.
        """
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç"
        cryptor = Cryptor()
        field_cryptor = FieldCryptor(AES, LOCAL_MODE)
        hashed_value = field_cryptor.hash(plaintext)
        ciphertext1 = field_cryptor.encrypt(plaintext, update=False)
        field_cryptor.update_crypt(ciphertext1)
        secret = field_cryptor.crypt_model_cls.objects.get(hash=hashed_value).secret
        field_cryptor.fetch_secret(HASH_PREFIX.encode(ENCODING) + hashed_value)
        self.assertEqual(plaintext, cryptor.aes_decrypt(secret, LOCAL_MODE))

    def test_get_secret(self):
        """Asserts secret is returned either as None or the secret.
        """
        cryptor = Cryptor()
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        plaintext = None
        ciphertext = field_cryptor.encrypt(plaintext)
        secret = field_cryptor.get_secret(ciphertext)
        self.assertIsNone(secret)
        plaintext = "erik is a pleeb!!∂ƒ˜∫˙ç"
        ciphertext = field_cryptor.encrypt(plaintext)
        secret = field_cryptor.get_secret(ciphertext)
        self.assertEqual(plaintext, cryptor.rsa_decrypt(secret, LOCAL_MODE))

    def test_rsa_field_as_none(self):
        """Asserts RSA roundtrip on None.
        """
        field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
        plaintext = None
        ciphertext = field_cryptor.encrypt(plaintext)
        self.assertIsNone(field_cryptor.decrypt(ciphertext))

    def test_aes_field_as_none(self):
        """Asserts AES roundtrip on None.
        """
        field_cryptor = FieldCryptor(AES, LOCAL_MODE)
        plaintext = None
        ciphertext = field_cryptor.encrypt(plaintext)
        self.assertIsNone(field_cryptor.decrypt(ciphertext))

    def test_model_with_encrypted_fields(self):
        """Asserts roundtrip via a model with encrypted fields.
        """
        firstname = "erik"
        identity = "123456789"
        comment = "erik is a pleeb!!∂ƒ˜∫˙ç"
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

    def test_model_with_encrypted_fields_as_none(self):
        """Asserts roundtrip via a model with encrypted fields.
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

    def test_model_with_unique_field(self):
        """Asserts unique constraint works on an encrypted field.

        identity = EncryptedTextField(
            verbose_name="Identity",
            unique=True)
        """
        firstname = "erik"
        identity = "123456789"
        comment = "erik is a pleeb!!∂ƒ˜∫˙ç"
        TestModel.objects.create(
            firstname=firstname, identity=identity, comment=comment
        )
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
