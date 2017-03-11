from django_crypto_fields.crypt_model_mixin import CryptModelMixin

from edc_base.model_mixins import BaseUuidModel


class Crypt(CryptModelMixin, BaseUuidModel):

    class Meta:
        app_label = 'django_crypto_fields'
        verbose_name = 'Crypt'
        unique_together = (('hash', 'algorithm', 'mode'),)
