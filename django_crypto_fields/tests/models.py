from django.db import models
from django.utils import timezone
from edc_model.models import BaseModel

from ..fields import EncryptedTextField, FirstnameField, IdentityField, LastnameField
from ..models import CryptoMixin


class TestModel(CryptoMixin, BaseModel):

    firstname = FirstnameField(verbose_name="First Name", null=True)

    lastname = LastnameField(verbose_name="Last Name", null=True)

    identity = IdentityField(verbose_name="Identity", unique=True)

    comment = EncryptedTextField(max_length=500, null=True)

    report_date = models.DateField(default=timezone.now)

    objects = models.Manager()

    class Meta:
        unique_together = ("firstname", "lastname")
