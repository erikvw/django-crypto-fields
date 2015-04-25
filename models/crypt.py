from django.db import models
from edc.device.dispatch.models import BaseDispatchSyncUuidModel


class Crypt (BaseDispatchSyncUuidModel):

    """ A secrets lookup model searchable by hash """

    hash = models.CharField(
        verbose_name="Hash",
        max_length=128,
        db_index=True,
        unique=True,
        )

    secret = models.TextField(
        verbose_name="Secret",
        )

    algorithm = models.CharField(
        max_length=25,
        db_index=True,
        null=True)

    mode = models.CharField(
        max_length=25,
        db_index=True,
        null=True)

    salt = models.CharField(
        max_length=50,
        null=True)

    objects = models.Manager()

    def deserialize_on_duplicate(self):
        return False

    def natural_key(self):
        return (self.hash, self.algorithm, self.mode,)

    class Meta:
        app_label = 'crypto_fields'
        db_table = 'bhp_crypto_crypt'
        verbose_name = 'Crypt'
        unique_together = (('hash', 'algorithm', 'mode'),)
