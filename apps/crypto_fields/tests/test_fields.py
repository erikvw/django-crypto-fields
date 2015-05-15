from django.test import TestCase

from apps.test_app.models import TestModel

from ..fields.base_field import BaseField


class TestCryptors(TestCase):

    def test_encrypt_rsa(self):
        """Assert deconstruct."""
        test_model = TestModel()
        fld_instance = test_model._meta.fields[-1:][0]
        name, path, args, kwargs = fld_instance.deconstruct()
        new_instance = BaseField(*args, **kwargs)
        # self.assertEqual(fld_instance.max_length, new_instance.max_length)
