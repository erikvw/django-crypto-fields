import os
from pathlib import Path
from tempfile import mkdtemp

from django.conf import settings
from django.test import TestCase
from django.test.utils import override_settings

from django_crypto_fields.exceptions import (
    DjangoCryptoFieldsKeyAlreadyExist,
    DjangoCryptoFieldsKeyPathDoesNotExist,
    DjangoCryptoFieldsKeyPathError,
)
from django_crypto_fields.key_path import KeyPath
from django_crypto_fields.keys import Keys, encryption_keys
from django_crypto_fields.utils import get_keypath_from_settings

production_path_with_keys = mkdtemp()
production_path_without_keys = mkdtemp()


class TestKeyCreator(TestCase):
    def setUp(self):
        encryption_keys.reset_and_delete_keys(verbose=False)
        encryption_keys.verbose = False
        encryption_keys.initialize()

    def tearDown(self):
        encryption_keys.reset_and_delete_keys(verbose=False)

    @override_settings(DJANGO_CRYPTO_FIELDS_KEY_PATH=mkdtemp())
    def test_keys_do_not_exist(self):
        encryption_keys.verbose = False
        encryption_keys.reset_and_delete_keys()
        for file in encryption_keys.filenames:
            self.assertFalse(Path(file).exists())

    @override_settings(DJANGO_CRYPTO_FIELDS_KEY_PATH=mkdtemp())
    def test_keys_exist(self):
        encryption_keys.reset_and_delete_keys(verbose=False)
        encryption_keys.verbose = False
        encryption_keys.initialize()
        for file in encryption_keys.filenames:
            self.assertTrue(Path(file).exists())

    @override_settings(DEBUG=False, DJANGO_CRYPTO_FIELDS_KEY_PATH="/blah/blah/blah/blah")
    def test_create_keys_defaults_to_non_production_path_and_raises(self):
        self.assertRaises(DjangoCryptoFieldsKeyPathDoesNotExist, KeyPath)

    @override_settings(
        DEBUG=False,
        DJANGO_CRYPTO_FIELDS_TEST_MODULE="blah.py",
        DJANGO_CRYPTO_FIELDS_KEY_PATH=None,
    )
    def test_create_keys_set_to_non_production_path_and_raises(self):
        self.assertRaises(DjangoCryptoFieldsKeyPathError, KeyPath)

    @override_settings(
        DEBUG=False,
        DJANGO_CRYPTO_FIELDS_TEST_MODULE="blah.py",
        DJANGO_CRYPTO_FIELDS_KEY_PATH=os.path.join(
            settings.BASE_DIR, "this/path/does/not/exist"
        ),
    )
    def test_invalid_production_path_raises(self):
        self.assertRaises(DjangoCryptoFieldsKeyPathDoesNotExist, KeyPath)
        self.assertRaises(DjangoCryptoFieldsKeyPathDoesNotExist, Keys)

    @override_settings(
        DEBUG=False,
        DJANGO_CRYPTO_FIELDS_TEST_MODULE="blah.py",
        DJANGO_CRYPTO_FIELDS_KEY_PATH=mkdtemp(),
    )
    def test_create_keys_does_not_overwrite_production_keys(self):
        keys = Keys(verbose=False)
        keys.reset()
        self.assertRaises(DjangoCryptoFieldsKeyAlreadyExist, keys.create_new_keys_or_raise)

    @override_settings(
        DEBUG=False,
        DJANGO_CRYPTO_FIELDS_KEY_PATH=None,
        DJANGO_CRYPTO_FIELDS_TEST_MODULE="blah.py",
    )
    def test_default_path_in_production_raises(self):
        self.assertFalse(settings.DEBUG)
        self.assertRaises(DjangoCryptoFieldsKeyPathError, KeyPath)

    @override_settings(DJANGO_CRYPTO_FIELDS_KEY_PATH=mkdtemp())
    def test_path(self):
        path = get_keypath_from_settings()
        key_path = KeyPath()
        self.assertEqual(str(key_path.path), path)

    def test_key_filenames_modes(self):
        self.assertEqual(len(list(encryption_keys.template.keys())), 3)
        self.assertEqual(list(encryption_keys.template.keys()), ["rsa", "aes", "salt"])

    @override_settings(DJANGO_CRYPTO_FIELDS_KEY_PATH=None)
    def test_key_filenames_key_types_per_mode(self):
        self.assertEqual(len(list(encryption_keys.template.keys())), 3)
        for value in encryption_keys.template.values():
            key_types = list(value.keys())
            key_types.sort()
            self.assertEqual(key_types, ["local", "restricted"])

    @override_settings(DJANGO_CRYPTO_FIELDS_KEY_PATH=None)
    def test_key_filenames_path_per_key_type(self):
        for mode in encryption_keys.template.values():
            for key_type in mode.values():
                self.assertIn(str(encryption_keys.path), str(list(key_type.values())[0]))
