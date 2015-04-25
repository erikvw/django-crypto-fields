from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError

from ..classes import FieldCryptor


class BaseEncryptedField(models.Field):

    """ A base field class to store sensitive data at rest in an encrypted
    format.

    * To maintain uniqueness and searchability, only the hash is ever
      stored in the model field.
    * The cipher is stored with the hash in the :class:`bhp_crypto.models.Crypt`
      cipher lookup model and is made available when required for
      de-encryption (e.g. the private key is available)
    * Salt, public key filename and private key filename are referred to
      via the settings file. """

    # see https://docs.djangoproject.com/en/dev/howto/
    #  custom-model-fields/#the-subfieldbase-metaclass
    description = 'Field class that stores values as encrypted'

    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        """
        Keyword Arguments (listing those of note only):
          max_length: length of table field for database. If settings.FIELD_MAX_LENGTH='default',
                      sets max_length to the default. If settings.FIELD_MAX_LENGTH='migration',
                      sets to default if less than default otherwise to the value defined on the model.
                      (default: length of hash plus prefixes e.g. 78L)
          widget: a custom widget (default: default django widget)
        """
        self.field_cryptor = FieldCryptor(self.algorithm, self.mode)
        # set the db field length based on the hash length (default length)
        # if converting a DB, longtext fields should not be set to
        # the default length until after the conversion is complete
        default_max_length = (self.field_cryptor.hasher.length +
                              len(self.field_cryptor.cryptor.HASH_PREFIX) +
                              len(self.field_cryptor.cryptor.SECRET_PREFIX))
        try:
            if settings.FIELD_MAX_LENGTH == 'default':
                max_length = default_max_length
            elif settings.FIELD_MAX_LENGTH == 'migration':
                max_length = kwargs.get('max_length', default_max_length)
                if max_length < default_max_length:
                    max_length = default_max_length
            else:
                raise TypeError('Invalid value for settings attribute FIELD_MAX_LENGTH. '
                                'Valid options are \'migration\' and \'default\'. '
                                'Got {0}'.format(settings.FIELD_MAX_LENGTH))
        except AttributeError as attribute_error:
            if 'FIELD_MAX_LENGTH' in str(attribute_error):
                raise AttributeError('Settings attribute \'FIELD_MAX_LENGTH\' not found. '
                                     'Set FIELD_MAX_LENGTH=\'migration\' before migrating an existing '
                                     'DB to use Encrypted Fields. Migrate, encrypt, then set FIELD_MAX_LENGTH=\'default\','
                                     'create a new schemamigration, and migrate again.')
            else:
                raise AttributeError(str(attribute_error))
        defaults = {'max_length': max_length}
        kwargs.update(defaults)
        super(BaseEncryptedField, self).__init__(*args, **kwargs)

    def get_max_length(self):
        return (self.field_cryptor.hasher.length +
                len(self.field_cryptor.cryptor.HASH_PREFIX) +
                len(self.field_cryptor.cryptor.SECRET_PREFIX))

    def is_encrypted(self, value):
        """ Wraps the cryptor method of same name """
        return self.field_cryptor.is_encrypted(self.to_string(value))

    def to_string(self, value):
        """ Users can override for non-string data types. """
        return value

    def decrypt(self, value, **kwargs):
        """ Wraps the cryptor method of same name """
        return self.field_cryptor.decrypt(value)

    def encrypt(self, value, **kwargs):
        """ Wraps the cryptor method of same name """
        return self.field_cryptor.encrypt(value)

    def validate_with_cleaned_data(self, attname, cleaned_data):
        """ May be overridden to test field data against other values
        in cleaned data.

        Should raise a forms.ValidationError if the test fails

        1. 'attname' is the key in cleaned_data for the value to be tested,
        2. 'cleaned_data' comes from django.forms clean() method """
        pass

    def to_python(self, value):
        """ Returns the decrypted value IF the private key is found, otherwise returns
        the encrypted value.

        Value comes from DB as a hash (e.g. <hash_prefix><hashed_value>). If DB value is being
        acccessed for the first time, value is not an encrypted value (not a prefix+hashed_value)."""
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
            # if it did not decrypt, set field to read only
            self.readonly = retval is not value
        return retval

    def get_prep_value(self, value, encrypt=True):
        """ Returns the hashed_value with prefix (or None) and, if needed, updates the secret lookup.

        Keyword arguments:
        encrypt -- if False, the value is returned as is (default True)

        """
        retval = value
        if value and encrypt:
            encrypted_value = self.encrypt(value)
            retval = self.field_cryptor.get_prep_value(encrypted_value, value)
        return retval

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
            if value != self.field_cryptor.cryptor.HASH_PREFIX:
                raise TypeError(('Value for lookup type {0} may only be \'{1}\' for '
                                 'fields using encryption.').format(lookup_type,
                                                                    self.field_cryptor.cryptor.HASH_PREFIX))
            return self.get_prep_value(value, encrypt=False)
        elif lookup_type == 'in':
            return [self.get_prep_value(v) for v in value]
        else:
            raise TypeError('Lookup type %r not supported.' % lookup_type)

    def get_internal_type(self):
        """This is a Charfield as we only ever store the hash, which is a \
        fixed length char. """
        return "CharField"

    def south_field_triple(self):
        "Returns a suitable description of this field for South."
        # We'll just introspect the _actual_ field.
        from south.modelsinspector import introspector
        field_class = "django.db.models.fields.CharField"
        args, kwargs = introspector(self)
        # That's our definition!
        return (field_class, args, kwargs)
