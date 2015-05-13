import datetime
import json

from django.conf import settings
from django import forms
from django.utils import timezone
from django.db import models
from django.utils import dateparse
from django.core import exceptions
from django.core.exceptions import ValidationError
from django.core.serializers.json import DjangoJSONEncoder

from .local_rsa_encryption_field import LocalRsaEncryptionField


class EncryptedDateField(LocalRsaEncryptionField, models.DateField):
    __metaclass__ = models.SubfieldBase
    form_widget = forms.DateInput
    form_field = forms.DateField
    save_format = "%Y:%m:%d"
    date_class = datetime.date
    max_raw_length = 10  # YYYY:MM:DD

    def to_python(self, value):
        """ Returns the decrypted date IF the private key is found, otherwise returns
               the encrypted value.

               Value comes from DB as a hash (e.g. <hash_prefix><hashed_value>). If DB value is being
               acccessed for the first time, value is not an encrypted value (not a prefix+hashed_value)."""
        if value is None:
            return value
        if isinstance(value, datetime.datetime):
            if settings.USE_TZ and timezone.is_aware(value):
                # Convert aware datetimes to the default time zone
                # before casting them to dates (#17742).
                default_timezone = timezone.get_default_timezone()
                value = timezone.make_naive(value, default_timezone)
            return value.date()
        if isinstance(value, datetime.date):
            return value

        retval = value
        if value:
            if not isinstance(value, basestring):
                try:
                    value = str(value)
                except:
                    raise TypeError('Expected basestring. Got {0}'.format(value))
            if not self.algorithm or not self.mode:
                raise ValidationError('Algorithm and mode not set for encrypted field')
            # decrypt will check if is_encrypted (e.g. enc1::<hash>)
            retval = self.decrypt(value)
            retval = json.loads(retval)

            try:
                retval = dateparse.parse_date(retval)
                if retval is not None:
                    return retval
            except ValueError:
                msg = self.error_messages['invalid_date'] % retval
                raise exceptions.ValidationError(msg)
            msg = self.error_messages['invalid'] % retval
            if msg:
                raise exceptions.ValidationError(msg)

    def get_prep_value(self, value, encrypt=True):
        """ Returns the hashed_value with prefix (or None) and, if needed, updates the secret lookup.

        Keyword arguments:
        encrypt -- if False, the value is returned as is (default True)

        """
        value = self.to_python(value)
        retval = value
        if value and encrypt:
            value = json.dumps(value, cls=DjangoJSONEncoder)
            encrypted_value = self.encrypt(value)
            retval = self.field_cryptor.get_prep_value(encrypted_value, value)
        return retval
