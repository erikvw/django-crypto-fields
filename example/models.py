from django.db import models
from django.utils import timezone

from edc_base.model.models import BaseModel

from django_crypto_fields.fields import EncryptedTextField, FirstnameField, LastnameField, IdentityField
from django_crypto_fields.mixins import CryptoMixin


class TestModel (CryptoMixin, BaseModel):

    firstname = FirstnameField(
        verbose_name="First Name",
        null=True)

    lastname = LastnameField(
        verbose_name="Last Name",
        null=True)

    identity = IdentityField(
        verbose_name="Identity",
        unique=True)

    comment = EncryptedTextField(
        max_length=500,
        null=True)

    report_date = models.DateField(
        default=timezone.now)

    objects = models.Manager()

    class Meta:
        app_label = 'example'
        unique_together = ('firstname', 'lastname')
