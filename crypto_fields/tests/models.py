from django.db import models

from edc_base.base.models import BaseModel

from ..fields import EncryptedTextField, FirstnameField, IdentityField


class TestModel (BaseModel):

    first_name = FirstnameField(
        verbose_name="First Name")

    identity = IdentityField(
        verbose_name="Identity",
        unique=True)

    comment = EncryptedTextField(
        verbose_name="AES",
        max_length=500)

    objects = models.Manager()

#     class Meta:
#         app_label = 'crypto_fields'
