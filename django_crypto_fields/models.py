from django.db import models
from edc_base.model_mixins import BaseUuidModel

from .model_mixins import CryptModelMixin
from edc_base.utils import get_utcnow


class Crypt(CryptModelMixin, BaseUuidModel):

    class Meta(CryptModelMixin.Meta):
        verbose_name = 'Crypt'


class KeyReference(models.Model):

    key_path = models.CharField(
        max_length=250)

    key_filenames = models.TextField(null=True)

    created = models.DateTimeField(default=get_utcnow, null=True)

    @property
    def current(self):
        return self.__class__.objects.all()[0]
