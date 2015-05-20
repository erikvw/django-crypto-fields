import types

from django.core.exceptions import ValidationError
from django.db import models

from ..classes import FieldCryptor
from ..classes.keys import keys
from ..constants import HASH_PREFIX, ENCODING
from ..exceptions import CipherError, EncryptionError, MalformedCiphertextError, EncryptionLookupError
from django_crypto_fields.constants import CIPHER_PREFIX


class BaseField(models.Field):

    description = 'Field class that stores values as encrypted'

    def __init__(self, *args, **kwargs):
        algorithm = kwargs.get('algorithm', 'rsa')
        mode = kwargs.get('mode', 'local')
        self.field_cryptor = FieldCryptor(algorithm, mode)
        max_length = kwargs.get('max_length', None) or len(HASH_PREFIX) + self.field_cryptor.hash_size
        if algorithm == 'rsa':
            max_message_length = keys.rsa_key_info[mode]['max_message_length']
            if max_length > max_message_length:
                raise EncryptionError(
                    '{} attribute \'max_length\' cannot exceed {} for RSA. Got {}. '
                    'Try setting \'algorithm\' = \'aes\'.'.format(
                        self.__class__.__name__, max_message_length, max_length))
        try:
            del kwargs['algorithm']
        except KeyError:
            pass
        try:
            del kwargs['mode']
        except KeyError:
            pass
        kwargs['max_length'] = max_length
        super(BaseField, self).__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super(BaseField, self).deconstruct()
        del kwargs["max_length"]
        return name, path, args, kwargs

    def to_string(self, value):
        """ Users can override for non-string data types. """
        return value

    def decrypt(self, value):
        if value is None:
            return value
        decrypted_value = None
        try:
            decrypted_value = self.field_cryptor.decrypt(value)
        except (CipherError, EncryptionError, MalformedCiphertextError) as e:
            raise ValidationError(e)
        if decrypted_value == value:
            self.readonly = True  # did not decrypt
        return decrypted_value

    def from_db_value(self, value, *args):
        if value is None:
            return value
        return self.decrypt(value)

    def to_python(self, value):
        if value is None or not isinstance(value, (str, bytes)):
            return value
        value = self.decrypt(value)
        return super(BaseField, self).to_python(value)

    def get_prep_value(self, value):
        """Returns the query value."""
        value = super(BaseField, self).get_prep_value(value)
        if value is None or not isinstance(value, (str, bytes)):
            return value
        ciphertext = self.field_cryptor.encrypt(value)
        return self.field_cryptor.get_query_value(ciphertext)

    def get_prep_lookup(self, lookup_type, value):
        """Raises an exception for unsupported lookups.

        Since the available value is the hash, only exact match lookup types are supported."""
        if lookup_type in {
            'startswith', 'istartswith', 'endswith', 'iendswith',
            'contains', 'icontains', 'iexact'
        }:
            raise EncryptionLookupError(
                'Unsupported lookup type for field class {}. Got \'{}\'.'.format(
                    self.__class__.__name__, lookup_type))
        return super(BaseField, self).get_prep_lookup(lookup_type, value)

    def get_internal_type(self):
        """This is a Charfield as we only ever store the hash, which is a \
        fixed length char. """
        return "BinaryField"
