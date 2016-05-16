from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.forms import widgets

from ..classes import FieldCryptor
from ..classes.keys import keys
from ..constants import HASH_PREFIX, RSA, LOCAL_MODE
from ..exceptions import CipherError, EncryptionError, MalformedCiphertextError


class BaseField(models.Field):

    description = 'Field class that stores values as encrypted'

    def __init__(self, algorithm, mode, *args, **kwargs):
        self.algorithm = algorithm or RSA
        self.mode = mode or LOCAL_MODE
        self.help_text = kwargs.get('help_text', '')
        if not self.help_text.startswith(' (Encryption:'):
            self.help_text = '{} (Encryption: {} {})'.format(
                self.help_text.split(' (Encryption:')[0], algorithm.upper(), mode)
        self.field_cryptor = FieldCryptor(self.algorithm, self.mode)
        self.max_length = kwargs.get('max_length', None) or len(HASH_PREFIX) + self.field_cryptor.hash_size
        if self.algorithm == RSA:
            max_message_length = keys.rsa_key_info[self.mode]['max_message_length']
            if self.max_length > max_message_length:
                raise EncryptionError(
                    '{} attribute \'max_length\' cannot exceed {} for RSA. Got {}. '
                    'Try setting \'algorithm\' = \'aes\'.'.format(
                        self.__class__.__name__, max_message_length, self.max_length))
        kwargs['max_length'] = self.max_length
        kwargs['help_text'] = self.help_text
        super(BaseField, self).__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super(BaseField, self).deconstruct()
        kwargs['help_text'] = self.help_text
        kwargs['max_length'] = self.max_length
        return name, path, args, kwargs

    def formfield(self, **kwargs):
        defaults = kwargs
        try:
            show_encrypted_values = settings.SHOW_CRYPTO_FORM_DATA
        except AttributeError:
            show_encrypted_values = True
        if not show_encrypted_values:
            defaults = {'disabled': True,
                        'widget': widgets.PasswordInput}
            defaults.update(kwargs)
        return super(BaseField, self).formfield(**defaults)

    def decrypt(self, value):
        decrypted_value = None
        if value is None or value in ['', b'']:
            return value
        try:
            decrypted_value = self.field_cryptor.decrypt(value)
            if not decrypted_value:
                self.readonly = True  # did not decrypt
                decrypted_value = value
        except (CipherError, EncryptionError, MalformedCiphertextError) as e:
            raise ValidationError(e)
        return decrypted_value

    def encrypt(self, value):
        if value is None or value in ['', b'']:
            return None
        encrypted_value = self.field_cryptor.encrypt(value)
        return encrypted_value

    def from_db_value(self, value, *args):
        if value is None:
            return value
        return self.decrypt(value)

    def to_python(self, value):
        if value is None:
            return value
        return self.decrypt(value)

    def get_prep_value(self, value):
        """Returns the encrypted value, including prefix, as the query value.

        Note: partial matches do not work. See get_prep_lookup()."""
        if value is None or value in ['']:
            return value
        encrypted_value = self.encrypt(value)
        return self.field_cryptor.get_query_value(encrypted_value)

    def get_prep_lookup(self, lookup_type, value):
        """Convert the value to a hash with prefix and pass to super.

        Since the available value is the hash, only exact match lookup types are supported."""
        hash_with_prefix = HASH_PREFIX.encode() + self.field_cryptor.hash(value)
        lookup_type = 'iexact'
        return super(BaseField, self).get_prep_lookup(lookup_type, hash_with_prefix)

    def get_internal_type(self):
        """This is a Charfield as we only ever store the hash, which is a \
        fixed length char. """
        return "CharField"

    def mask(self, value, mask=None):
        return self.field_cryptor.mask(value, mask)
