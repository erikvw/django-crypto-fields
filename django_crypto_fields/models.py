from .model_mixins import CryptModelMixin

from edc_base.model_mixins import BaseUuidModel


class Crypt(CryptModelMixin, BaseUuidModel):

    class Meta(CryptModelMixin.Meta):
        verbose_name = 'Crypt'
