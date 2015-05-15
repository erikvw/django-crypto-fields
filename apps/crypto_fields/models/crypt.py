from django.db import models

from apps.edc.base.models import BaseModel


class Crypt (BaseModel):

    """ A secrets lookup model searchable by hash """

    hash = models.BinaryField(
        verbose_name="Hash",
        max_length=128,
        db_index=True,
        unique=True)

    secret = models.BinaryField(
        verbose_name="Secret")

    algorithm = models.CharField(
        max_length=25,
        db_index=True,
        null=True)

    mode = models.CharField(
        max_length=25,
        db_index=True,
        null=True)

    objects = models.Manager()

    def natural_key(self):
        return (self.hash, self.algorithm, self.mode,)

    class Meta:
        app_label = 'crypto_fields'
        verbose_name = 'Crypt'
        unique_together = (('hash', 'algorithm', 'mode'),)
