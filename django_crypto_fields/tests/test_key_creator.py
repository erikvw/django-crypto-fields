import os

from django.apps import apps as django_apps
from django.test.utils import override_settings
from django.test import TestCase, tag
from tempfile import mkdtemp

from ..key_files import KeyFiles
from ..key_path import KeyPath, DjangoCryptoFieldsKeyPathError
from ..key_creator import KeyCreator, DjangoCryptoFieldsKeyAlreadyExist


class TestKeyCreator(TestCase):

    def setUp(self):
        self.tmp_key_path = mkdtemp()
        app_config = django_apps.get_app_config('django_crypto_fields')
        if app_config.temp_path:
            key_files = KeyFiles(key_path=app_config.temp_path)
            for file in key_files.files:
                os.remove(file)

    def tearDown(self):
        key_files = KeyFiles(key_path=self.tmp_key_path)
        for file in key_files.files:
            os.remove(file)

    def test_creator(self):
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

    def test_create_keys_does_not_overwrite(self):
        creator = KeyCreator()
        creator.create_keys()
        key_files = KeyFiles(key_path=creator.key_path)
        self.assertTrue(key_files.key_files_exist)
        self.assertRaises(
            DjangoCryptoFieldsKeyAlreadyExist,
            creator.create_keys)

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
