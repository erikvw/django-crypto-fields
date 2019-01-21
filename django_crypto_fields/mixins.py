from django.db import models

from .fields import BaseField


class CryptoMixin(models.Model):
    @classmethod
    def encrypted_fields(cls):
        return [fld.name for fld in cls._meta.fields if isinstance(fld, BaseField)]

    class Meta:
        abstract = True
