from decimal import Decimal
from .local_rsa_encryption_field import LocalRsaEncryptionField


class EncryptedDecimalField(LocalRsaEncryptionField):

    description = "local-rsa encrypted field for 'IntegerField'"

    def __init__(self, *args, **kwargs):
        #models.DecimalField(..., max_digits=5, decimal_places=2)
        if not 'max_digits' in kwargs.keys():
            raise AttributeError('EncryptedDecimalField requires attribute \'max_digits\. Got none')
        elif 'max_digits' in kwargs.keys():
            try:
                int(kwargs.get('max_digits'))
            except:
                raise AttributeError('EncryptedDecimalField attribute \'max_digits\ must be an '
                                     'integer. Got {0}'.format(kwargs.get('max_digits')))
        if not 'decimal_places' in kwargs.keys():
            raise AttributeError('EncryptedDecimalField requires attribute \'decimal_places\. Got none')
        elif 'decimal_places' in kwargs.keys():
            try:
                int(kwargs.get('decimal_places'))
            except:
                raise AttributeError('EncryptedDecimalField attribute \'decimal_places\ must '
                                     'be an integer. Got {0}'.format(kwargs.get('decimal_places')))
        decimal_decimal_places = int(kwargs.get('decimal_places'))
        decimal_max_digits = int(kwargs.get('max_digits'))
        del kwargs['decimal_places']
        del kwargs['max_digits']
        super(EncryptedDecimalField, self).__init__(*args, **kwargs)
        self.decimal_decimal_places = decimal_decimal_places
        self.decimal_max_digits = decimal_max_digits

    def to_string(self, value):
        if isinstance(value, basestring):
            raise TypeError('Expected basestring. Got {0}'.format(value))
        return str(value)

    def to_python(self, value):
        """ Returns as integer """
        retval = super(EncryptedDecimalField, self).to_python(value)
        if retval:
            if not self.field_cryptor.is_encrypted(retval):
                retval = Decimal(retval).to_eng_string()
        return retval
