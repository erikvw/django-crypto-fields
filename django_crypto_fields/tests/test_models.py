from django.db.utils import IntegrityError
from django.test import TestCase

from ..fields.base_field import BaseField
from ..exceptions import EncryptionLookupError

from .models import TestModel


class TestModels(TestCase):

    def test_encrypt_rsa(self):
        """Assert deconstruct."""
        test_model = TestModel()
        fld_instance = test_model._meta.fields[-1:][0]
        name, path, args, kwargs = fld_instance.deconstruct()
        new_instance = BaseField(*args, **kwargs)
        # self.assertEqual(fld_instance.max_length, new_instance.max_length)

    def test_list_encrypted_fields(self):
        self.assertEquals(len(TestModel.encrypted_fields()), 4)

    def test_blank(self):
        TestModel.objects.create(firstname='Erik1', identity='11111111', comment='')
        self.assertEqual(1, TestModel.objects.filter(comment='').count())

    def test_equals(self):
        TestModel.objects.create(firstname='Erik1', identity='11111111', comment='')
        self.assertEqual(1, TestModel.objects.filter(firstname='Erik1').count())

    def test_null(self):
        TestModel.objects.create(identity='11111111', comment='no comment')
        self.assertEqual(1, TestModel.objects.filter(firstname__isnull=True).count())

    def test_exact(self):
        TestModel.objects.create(firstname='Erik1', identity='11111111', comment='')
        self.assertEqual(1, TestModel.objects.filter(firstname__exact='Erik1').count())

    def test_iexact(self):
        TestModel.objects.create(firstname='Erik1', identity='11111111', comment='')
        # self.assertEqual(1, TestModel.objects.filter(firstname__iexact='Erik1').count())
        self.assertRaises(EncryptionLookupError, TestModel.objects.filter, firstname__iexact='Erik1')

    def test_contains(self):
        TestModel.objects.create(firstname='Erik1', identity='11111111', comment='')
        # self.assertEqual(1, TestModel.objects.filter(firstname__contains='k1').count())
        self.assertRaises(EncryptionLookupError, TestModel.objects.filter, firstname__contains='k1')

    def test_icontains(self):
        TestModel.objects.create(firstname='Erik1', identity='11111111', comment='')
        # self.assertEqual(1, TestModel.objects.filter(firstname__icontains='k1').count())
        self.assertRaises(EncryptionLookupError, TestModel.objects.filter, firstname__icontains='k1')

    def test_in(self):
        TestModel.objects.create(firstname='Erik1', identity='11111111', comment='no comment')
        TestModel.objects.create(firstname='Erik2', identity='11111112', comment='no comment')
        TestModel.objects.create(firstname='Erik3', identity='11111113', comment='no comment')
        TestModel.objects.create(firstname='Erik4', identity='11111114', comment='no comment')
        self.assertEqual(2, TestModel.objects.filter(firstname__in=['Erik1', 'Erik2']).count())

    def test_unique(self):
        TestModel.objects.create(firstname='Erik1', identity='11111111', comment='no comment')
        TestModel.objects.create(firstname='Erik2', identity='11111112', comment='no comment')
        self.assertRaises(IntegrityError, TestModel.objects.create, firstname='Erik1', identity='11111111', comment='no comment')

    def test_unique_together(self):
        TestModel.objects.create(firstname='Erik1', lastname='vw', identity='11111111', comment='no comment')
        TestModel.objects.create(firstname='Erik2', lastname='vw', identity='11111112', comment='no comment')
        self.assertRaises(IntegrityError, TestModel.objects.create, firstname='Erik1', lastname='vw', identity='11111113', comment='no comment')

    def test_startswith(self):
        TestModel.objects.create(firstname='Eriak1', identity='11111111', comment='no comment')
        TestModel.objects.create(firstname='Eriak2', identity='11111112', comment='no comment')
        TestModel.objects.create(firstname='Eriek3', identity='11111113', comment='no comment')
        TestModel.objects.create(firstname='Eriek4', identity='11111114', comment='no comment')
        # self.assertEqual(2, TestModel.objects.filter(firstname__startswith='Eria').count())
        self.assertRaises(EncryptionLookupError, TestModel.objects.filter, firstname__startswith='Eria')

    def test_endsswith(self):
        TestModel.objects.create(firstname='Eriak1', identity='11111111', comment='no comment')
        TestModel.objects.create(firstname='Eriak2', identity='11111112', comment='no comment')
        TestModel.objects.create(firstname='Eriek3', identity='11111113', comment='no comment')
        TestModel.objects.create(firstname='Eriek4', identity='11111114', comment='no comment')
        # self.assertEqual(1, TestModel.objects.filter(firstname__endswith='ak2').count())
        self.assertRaises(EncryptionLookupError, TestModel.objects.filter, firstname__endswith='ak2')
