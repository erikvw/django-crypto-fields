from django.test import TestCase

from ..fields.base_field import BaseField

from .models import TestModel


class TestCryptors(TestCase):

    def test_encrypt_rsa(self):
        """Assert deconstruct."""
        test_model = TestModel()
        fld_instance = test_model._meta.fields[-1:][0]
        name, path, args, kwargs = fld_instance.deconstruct()
        new_instance = BaseField(*args, **kwargs)
        # self.assertEqual(fld_instance.max_length, new_instance.max_length)

    def test_list_encrypted_fields(self):
        self.assertEquals(len(TestModel.encrypted_fields()), 3)
