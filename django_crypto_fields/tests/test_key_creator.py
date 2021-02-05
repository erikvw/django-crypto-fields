import os
from tempfile import mkdtemp

from django.apps import apps as django_apps
from django.conf import settings
from django.test import TestCase, tag  # noqa
from django.test.utils import override_settings

from ..key_creator import DjangoCryptoFieldsKeyAlreadyExist, KeyCreator
from ..key_files import KeyFiles
from ..key_path import (
    DjangoCryptoFieldsKeyPathDoesNotExist,
    DjangoCryptoFieldsKeyPathError,
    KeyPath,
)

production_path_with_keys = mkdtemp()
production_path_without_keys = mkdtemp()


class TestKeyCreator(TestCase):
    def setUp(self):
        self.tmp_key_path = KeyPath(path=mkdtemp())
        self.key_path = KeyPath(path=production_path_with_keys)
        self.key_path_without_keys = KeyPath(path=production_path_without_keys)
        self.key_files = KeyFiles(key_path=self.key_path)

    def tearDown(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        for file in key_files.files:
            os.remove(file)
        key_files = KeyFiles(key_path=self.key_path)
        for file in key_files.files:
            os.remove(file)
        key_files = KeyFiles(key_path=self.key_path_without_keys)
        for file in key_files.files:
            os.remove(file)

    @override_settings(DEBUG=True)
    def test_creator_creates_tmp_keys_for_debug_true(self):
        app_config = django_apps.get_app_config("django_crypto_fields")
        self.assertTrue(app_config.key_files.key_files_exist)

    def test_create_keys(self):
        key_path = KeyPath(path=mkdtemp())
        key_files = KeyFiles(key_path=key_path)
        creator = KeyCreator(key_files=key_files)
        creator.create_keys()

    def test_create_keys_exist(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        self.assertFalse(key_files.key_files_exist)
        creator = KeyCreator(key_files=key_files)
        creator.create_keys()
        key_files = KeyFiles(key_path=self.tmp_key_path)
        self.assertTrue(key_files.key_files_exist)

    @override_settings(DEBUG=False, KEY_PATH=KeyPath.non_production_path)
    def test_create_keys_defaults_to_non_production_path_and_raises(self):
        self.assertRaises(DjangoCryptoFieldsKeyPathError, KeyPath)

    @override_settings(
        DEBUG=False, KEY_PATH=os.path.join(settings.BASE_DIR, "crypto_fields")
    )
    def test_create_keys_set_to_non_production_path_and_raises(self):
        self.assertRaises(DjangoCryptoFieldsKeyPathError, KeyPath)

    @override_settings(
        DEBUG=False,
        KEY_PATH=os.path.join(settings.BASE_DIR, "this_path_does_not_exist"),
    )
    def test_create_keys_set_to_production_path_and_raises(self):
        app_config = django_apps.get_app_config("django_crypto_fields")
        self.assertNotEqual(
            app_config.key_path.path,
            os.path.join(settings.BASE_DIR, "this_path_does_not_exist"),
        )
        self.assertRaises(
            DjangoCryptoFieldsKeyPathDoesNotExist,
            KeyPath,
            path=os.path.join(settings.BASE_DIR, "this_path_does_not_exist"),
        )

    @override_settings(DEBUG=False, KEY_PATH=production_path_with_keys)
    def test_create_keys_does_not_overwrite_production_keys(self):
        app_config = django_apps.get_app_config("django_crypto_fields")
        creator = KeyCreator(key_files=app_config.key_files)
        self.assertRaises(DjangoCryptoFieldsKeyAlreadyExist, creator.create_keys)

    @override_settings(DEBUG=False, KEY_PATH=production_path_without_keys)
    def test_create_keys_set_to_production_path_and_raises3(self):
        app_config = django_apps.get_app_config("django_crypto_fields")
        # because "test" in sys.argv, this fails
        self.assertNotEqual(app_config.key_path.path, production_path_without_keys)
        self.assertEqual(settings.KEY_PATH, production_path_without_keys)
        key_path = KeyPath(path=settings.KEY_PATH)
        key_files = KeyFiles(key_path=key_path)
        self.assertEqual(len(key_files.files), 0)
        creator = KeyCreator(key_files=key_files)
        creator.create_keys()
        key_files = KeyFiles(key_path=key_path)
        self.assertGreater(len(key_files.files), 0)

    #     @override_settings(DEBUG=True, KEY_PATH=None)
    #     def test_default_path_for_debug(self):
    #         """Because this is a test, sets to the tmp path.
    #
    #         Behavior is different for runserver.
    #         """
    #         app_config = django_apps.get_app_config("django_crypto_fields")
    #         self.assertEqual(app_config.key_path.path, app_config.temp_path)

    @override_settings(DEBUG=False)
    def test_default_path_in_production_raises(self):
        self.assertFalse(settings.DEBUG)
        self.assertRaises(
            DjangoCryptoFieldsKeyPathError, KeyPath, path=KeyPath.non_production_path
        )

    def test_path(self):
        path = mkdtemp()
        key_path = KeyPath(path=path)
        self.assertEqual(key_path.path, path)

    def test_key_filenames_modes(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        self.assertEqual(len(list(key_files.key_filenames.keys())), 3)
        self.assertEqual(list(key_files.key_filenames.keys()), ["rsa", "aes", "salt"])

    def test_key_filenames_key_types_per_mode(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        self.assertEqual(len(list(key_files.key_filenames.keys())), 3)
        for value in key_files.key_filenames.values():
            key_types = list(value.keys())
            key_types.sort()
            self.assertEqual(key_types, ["local", "restricted"])

    def test_key_filenames_path_per_key_type(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)

        for mode in key_files.key_filenames.values():
            for key_type in mode.values():
                self.assertIn(key_files.key_path.path, list(key_type.values())[0])
