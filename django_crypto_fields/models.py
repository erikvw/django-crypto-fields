from django_crypto_fields.crypt_model_mixin import CryptModelMixin

from edc_base.model.models import BaseUuidModel, BaseModel


class Crypt(CryptModelMixin, BaseModel):

    class Meta:
        app_label = 'django_crypto_fields'
        verbose_name = 'Crypt'
        unique_together = (('hash', 'algorithm', 'mode'),)
