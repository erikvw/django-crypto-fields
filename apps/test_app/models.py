from django.db import models

from base.models import BaseModel

from apps.crypto_fields.fields import EncryptedAesCharField, EncryptedFirstnameField, EncryptedTextField


class TestModel (BaseModel):

    first_name = EncryptedFirstnameField(
        verbose_name="First Name")

    identity = EncryptedTextField(
        verbose_name="Identity",
        unique=True)

    comment = EncryptedAesCharField(
        verbose_name="AES",
        max_length=500)

    objects = models.Manager()

    class Meta:
        app_label = 'test_app'
