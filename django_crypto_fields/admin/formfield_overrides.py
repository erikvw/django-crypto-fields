from django.contrib.admin.options import FORMFIELD_FOR_DBFIELD_DEFAULTS
from django.db import models

from django_crypto_fields.fields import (
    EncryptedCharField,
    EncryptedDateField,
    EncryptedDateTimeField,
    EncryptedIntegerField,
    EncryptedTextField,
)

FORMFIELD_FOR_DBFIELD_DEFAULTS.update(
    {
        EncryptedCharField: FORMFIELD_FOR_DBFIELD_DEFAULTS[models.CharField],
        EncryptedDateField: FORMFIELD_FOR_DBFIELD_DEFAULTS[models.DateField],
        EncryptedDateTimeField: FORMFIELD_FOR_DBFIELD_DEFAULTS[models.DateTimeField],
        EncryptedIntegerField: FORMFIELD_FOR_DBFIELD_DEFAULTS[models.IntegerField],
        EncryptedTextField: FORMFIELD_FOR_DBFIELD_DEFAULTS[models.TextField],
    }
)


formfield_overrides = FORMFIELD_FOR_DBFIELD_DEFAULTS
