from edc_base.model_mixins import BaseUuidModel

from .model_mixins import CryptModelMixin


class Crypt(CryptModelMixin, BaseUuidModel):

    class Meta(CryptModelMixin.Meta):
        verbose_name = 'Crypt'
