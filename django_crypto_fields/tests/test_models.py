from django.db.utils import IntegrityError
from django.test import TestCase, tag  # noqa

from ..fields.base_field import BaseField
from .models import TestModel


class TestModels(TestCase):
    def test_encrypt_rsa(self):
        """Assert deconstruct.
        """
        test_model = TestModel()
        for fld in test_model._meta.fields:
            if isinstance(fld, BaseField):
                _, _, args, kwargs = fld.deconstruct()
                new = BaseField(fld.algorithm, fld.mode, *args, **kwargs)
                self.assertEqual(fld.algorithm, new.algorithm)
                self.assertEqual(fld.mode, new.mode)

    def test_list_encrypted_fields(self):
        self.assertEqual(len(TestModel.encrypted_fields()), 4)

    def test_change(self):
        test_model = TestModel.objects.create(
            firstname="Erik1", identity="11111111", comment=""
        )
        test_model.firstname = "Erik2"
        test_model.save()
        TestModel.objects.get(firstname="Erik2")

    def test_type(self):
        TestModel.objects.create(firstname="Erik1", identity="11111111", comment="")
        test_model = TestModel.objects.get(firstname="Erik1")
        self.assertEqual(type(test_model.firstname), type("Erik1"))

    def test_blank(self):
        TestModel.objects.create(firstname="Erik1", identity="11111111", comment="")
        self.assertEqual(1, TestModel.objects.filter(comment="").count())

    def test_equals(self):
        TestModel.objects.create(firstname="Erik1", identity="11111111", comment="")
        self.assertEqual(1, TestModel.objects.filter(firstname="Erik1").count())

    def test_null(self):
        TestModel.objects.create(identity="11111111", comment="no comment")
        self.assertEqual(1, TestModel.objects.filter(firstname__isnull=True).count())

    def test_exact(self):
        TestModel.objects.create(firstname="Erik1", identity="11111111", comment="")
        self.assertEqual(1, TestModel.objects.filter(firstname__exact="Erik1").count())

    def test_in(self):
        TestModel.objects.create(
            firstname="Erik1", identity="11111111", comment="no comment"
        )
        TestModel.objects.create(
            firstname="Erik2", identity="11111112", comment="no comment"
        )
        TestModel.objects.create(
            firstname="Erik3", identity="11111113", comment="no comment"
        )
        TestModel.objects.create(
            firstname="Erik4", identity="11111114", comment="no comment"
        )
        self.assertEqual(
            2, TestModel.objects.filter(firstname__in=["Erik1", "Erik2"]).count()
        )

    def test_unique(self):
        TestModel.objects.create(
            firstname="Erik1", identity="11111111", comment="no comment"
        )
        TestModel.objects.create(
            firstname="Erik2", identity="11111112", comment="no comment"
        )
        self.assertRaises(
            IntegrityError,
            TestModel.objects.create,
            firstname="Erik1",
            identity="11111111",
            comment="no comment",
        )

    def test_unique_together(self):
        TestModel.objects.create(
            firstname="Erik1", lastname="vw", identity="11111111", comment="no comment"
        )
        TestModel.objects.create(
            firstname="Erik2", lastname="vw", identity="11111112", comment="no comment"
        )
        self.assertRaises(
            IntegrityError,
            TestModel.objects.create,
            firstname="Erik1",
            lastname="vw",
            identity="11111113",
            comment="no comment",
        )
