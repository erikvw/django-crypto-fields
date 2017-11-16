import os

from django.apps import apps as django_apps
from django.conf import settings
from django.test.utils import override_settings
from django.test import TestCase, tag
from tempfile import mkdtemp

from ..key_files import KeyFiles
from ..key_path import KeyPath, DjangoCryptoFieldsKeyPathError
from ..key_path import DjangoCryptoFieldsKeyPathDoesNotExist
from ..key_creator import KeyCreator, DjangoCryptoFieldsKeyAlreadyExist


production_path_with_keys = os.path.join(settings.BASE_DIR, 'production_keys1')
production_path_without_keys = os.path.join(
    settings.BASE_DIR, 'production_keys2')


class TestKeyCreator(TestCase):

    def setUp(self):
        self.tmp_key_path = mkdtemp()
        app_config = django_apps.get_app_config('django_crypto_fields')
        if app_config.temp_path:
            key_files = KeyFiles(key_path=app_config.temp_path)
            for file in key_files.files:
                os.remove(file)

        key_path = os.path.join(settings.BASE_DIR, 'production_keys1')
        creator = KeyCreator(key_path=key_path)
        try:
            creator.create_keys()
        except DjangoCryptoFieldsKeyAlreadyExist:
            pass

    def tearDown(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        for file in key_files.files:
            os.remove(file)
        key_files = KeyFiles(key_path=production_path_without_keys)
        for file in key_files.files:
            os.remove(file)

    @override_settings(DEBUG=True)
    def test_creator_creates_tmp_keys_for_debug_true(self):
        KeyCreator()

    def test_create_keys(self):
        creator = KeyCreator(key_path=self.tmp_key_path)
        creator.create_keys()

    def test_create_keys_exist(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        self.assertFalse(key_files.key_files_exist)
        creator = KeyCreator(key_path=self.tmp_key_path)
        creator.create_keys()
        key_files = KeyFiles(key_path=self.tmp_key_path)
        self.assertTrue(key_files.key_files_exist)

    @tag('1')
    @override_settings(DEBUG=False)
    def test_create_keys_defaults_to_non_production_path_and_raises(self):
        self.assertRaises(
            DjangoCryptoFieldsKeyPathError,
            KeyCreator)

    @tag('1')
    @override_settings(DEBUG=False, KEY_PATH=os.path.join(settings.BASE_DIR, 'crypto_fields'))
    def test_create_keys_set_to_non_production_path_and_raises(self):
        self.assertRaises(
            DjangoCryptoFieldsKeyPathError,
            KeyCreator)

    @tag('1')
    @override_settings(DEBUG=False, KEY_PATH=os.path.join(settings.BASE_DIR, 'production'))
    def test_create_keys_set_to_production_path_and_raises(self):
        self.assertRaises(
            DjangoCryptoFieldsKeyPathDoesNotExist,
            KeyCreator)

    @tag('1')
    @override_settings(DEBUG=False, KEY_PATH=production_path_with_keys)
    def test_create_keys_does_not_overwrite_production_keys(self):
        creator = KeyCreator()
        self.assertRaises(
            DjangoCryptoFieldsKeyAlreadyExist,
            creator.create_keys)

    @tag('1')
    @override_settings(DEBUG=False, KEY_PATH=production_path_without_keys)
    def test_create_keys_set_to_production_path_and_raises3(self):
        key_files = KeyFiles(key_path=production_path_without_keys)
        self.assertEqual(len(key_files.files), 0)
        creator = KeyCreator()
        creator.create_keys()
        key_files = KeyFiles(key_path=production_path_without_keys)
        self.assertGreater(len(key_files.files), 0)

    @override_settings(DEBUG=True)
    def test_default_path(self):
        key_path = KeyPath(force_key_path=True)
        self.assertEqual(key_path.key_path, KeyPath.non_production_path)

    @override_settings(DEBUG=False)
    def test_default_path_in_production_raises(self):
        self.assertRaises(
            DjangoCryptoFieldsKeyPathError, KeyPath, force_key_path=True)

    def test_path(self):
        key_path = KeyPath(key_path=self.tmp_key_path, force_key_path=True)
        self.assertEqual(key_path.key_path, self.tmp_key_path)

    def test_key_filenames_modes(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        self.assertEqual(len(list(key_files.key_filenames.keys())), 3)
        self.assertEqual(list(key_files.key_filenames.keys()),
                         ['rsa', 'aes', 'salt'])

    def test_key_filenames_key_types_per_mode(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        self.assertEqual(len(list(key_files.key_filenames.keys())), 3)
        for value in key_files.key_filenames.values():
            key_types = list(value.keys())
            key_types.sort()
            self.assertEqual(key_types, ['local', 'restricted'])

    def test_key_filenames_path_per_key_type(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)

        for mode in key_files.key_filenames.values():
            for key_type in mode.values():
                self.assertIn(key_files.key_path, list(key_type.values())[0])
