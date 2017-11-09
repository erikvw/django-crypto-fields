from django.conf import settings
from edc_base.model_mixins import BaseUuidModel

from .model_mixins import CryptModelMixin


class Crypt(CryptModelMixin, BaseUuidModel):

    class Meta(CryptModelMixin.Meta):
        verbose_name = 'Crypt'


if settings.APP_NAME == 'django_crypto_fields':
    from .tests import models
