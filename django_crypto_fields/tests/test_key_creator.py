from django.test import TestCase, tag
from django_crypto_fields.key_path_handler import KeyPathHandler
from tempfile import mkdtemp

from ..default_key_path import default_key_path
from ..key_creator import KeyCreator, DjangoCryptoFieldsKeyAlreadyExist


class TestKeyCreator(TestCase):

    def setUp(self):
        self.tmp_key_path = mkdtemp()

    @tag('1')
    def test_creator(self):
        KeyCreator(key_path=self.tmp_key_path)

    @tag('1')
    def test_create_keys(self):
        creator = KeyCreator(key_path=self.tmp_key_path)
        creator.create_keys()

    @tag('1')
    def test_create_keys_exist(self):
        obj = KeyPathHandler(key_path=self.tmp_key_path)
        self.assertFalse(obj.key_files_exist)
        creator = KeyCreator(key_path=self.tmp_key_path)
        creator.create_keys()
        obj = KeyPathHandler(key_path=self.tmp_key_path)
        self.assertTrue(obj.key_files_exist)

    @tag('1')
    def test_create_keys_does_not_overwrite(self):
        creator = KeyCreator(key_path=self.tmp_key_path)
        creator.create_keys()
        obj = KeyPathHandler(key_path=self.tmp_key_path)
        self.assertTrue(obj.key_files_exist)
        self.assertRaises(
            DjangoCryptoFieldsKeyAlreadyExist,
            creator.create_keys)

    @tag('2')
    def test_default_path(self):
        obj = KeyPathHandler()
        self.assertEqual(obj.key_path, default_key_path)

    @tag('2')
    def test_path(self):
        obj = KeyPathHandler(key_path=self.tmp_key_path)
        self.assertEqual(obj.key_path, self.tmp_key_path)

    @tag('2')
    def test_key_filenames_modes(self):
        obj = KeyPathHandler(key_path=self.tmp_key_path)
        self.assertEqual(len(list(obj.key_filenames.keys())), 3)
        self.assertEqual(list(obj.key_filenames.keys()),
                         ['rsa', 'aes', 'salt'])

    @tag('2')
    def test_key_filenames_key_types_per_mode(self):
        obj = KeyPathHandler(key_path=self.tmp_key_path)
        self.assertEqual(len(list(obj.key_filenames.keys())), 3)
        for value in obj.key_filenames.values():
            key_types = list(value.keys())
            key_types.sort()
            self.assertEqual(key_types, ['local', 'restricted'])

    @tag('2')
    def test_key_filenames_path_per_key_type(self):
        obj = KeyPathHandler(key_path=self.tmp_key_path)

        for mode in obj.key_filenames.values():
            for key_type in mode.values():
                self.assertIn(obj.key_path, list(key_type.values())[0])
