from django.core.exceptions import ValidationError
from django.db import models

from ..classes import FieldCryptor
from ..classes.constants import HASH_PREFIX, ENCODING
from ..exceptions import CipherError, EncryptionError, MalformedCiphertextError


class BaseField(models.Field):

    description = 'Field class that stores values as encrypted'

    def __init__(self, *args, **kwargs):
        algorithm = kwargs.get('algorithm', 'rsa')
        mode = kwargs.get('mode', 'local')
        self.field_cryptor = FieldCryptor(algorithm, mode)
        max_length = kwargs.get('max_length', None) or len(HASH_PREFIX) + self.field_cryptor.hash_size
        if algorithm == 'rsa':
            max_message_length = self.field_cryptor.cryptor.rsa_key_info[mode]['max_message_length']
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

    def from_db_value(self, value, expression, connection, context):
        if value is None:
            return value
        return self.decrypt(value)

    def to_python(self, value):
        if value is None:
            return value
        return self.decrypt(value)

    def get_prep_value(self, value, encrypt=None):
        """ Returns the hashed_value with prefix (or None) and, if needed, updates the cipher_model.

        Keyword arguments:
            encrypt -- if False, the value is returned as is (default True)
        """
        if value is None:
            return value
        encrypt = True if encrypt is None else encrypt
        if encrypt:
            ciphertext = self.field_cryptor.encrypt(value)
            if ciphertext != value:
                self.field_cryptor.update_cipher_model(ciphertext)
            value = HASH_PREFIX.encode(ENCODING) + self.field_cryptor.get_hash(ciphertext)
        return value

    def get_prep_lookup(self, lookup_type, value):
        """ Only decrypts the stored value to handle 'exact' and 'in'
        but excepts 'icontains' as if it is 'exact' so that the admin
        search fields work.

        Also, 'startswith' does not decrypt and may only be used to check for the hash_prefix.
        All others are errors.
        """
        if lookup_type == 'exact' or lookup_type == 'icontains':
            return self.get_prep_value(value)
        elif lookup_type == 'isnull':
            if type(value) != bool:
                raise TypeError(('Value for lookup type \'{0}\' must be a boolean '
                                 'for fields using encryption. Got {1}').format(lookup_type, value))
            return self.get_prep_value(value, encrypt=False)
        elif lookup_type == 'startswith':
            # allow to test field value for the hash_prefix only, NO searching on the hash
            if value != HASH_PREFIX:
                raise TypeError(('Value for lookup type {0} may only be \'{1}\' for '
                                 'fields using encryption.').format(lookup_type,
                                                                    HASH_PREFIX))
            return self.get_prep_value(value, encrypt=False)
        elif lookup_type == 'in':
            return [self.get_prep_value(v) for v in value]
        else:
            raise TypeError('Lookup type %r not supported.' % lookup_type)

    def get_internal_type(self):
        """This is a Charfield as we only ever store the hash, which is a \
        fixed length char. """
        return "BinaryField"
