from edc.core.bhp_string.classes import StringHelper


class BaseCryptor(StringHelper):

    # prefix for each segment of an encrypted value, also used to calculate
    # field length for model.
    HASH_PREFIX = 'enc1:::'  # uses a prefix to flag as encrypted
    SECRET_PREFIX = 'enc2:::'  # like django-extensions does
    IV_PREFIX = 'iv:::'

    def is_encrypted(self, value, prefix=None):
        """ Determines that a value string is encrypted if it starts
        with 'self.HASH_PREFIX' or whichever prefix is passed.

        ..warning:: This method can only detect encrypted values coming from
                    FieldCryptor since it looks for a prefix. The method
                    should be moved up to FieldCryptor. See tests."""
        if not value:
            is_encrypted = False
        else:
            if not isinstance(value, basestring):
                raise TypeError('Expected basestring. Got {0}'.format(value))
            if prefix is None:
                prefix = self.HASH_PREFIX
            if value == prefix:
                raise TypeError('Expected a string value, got just the '
                                 'encryption prefix.')
            if value.startswith(prefix):
                is_encrypted = True
            else:
                is_encrypted = False
        return is_encrypted

    def mask(self, value, mask='<encrypted>'):
        """ Help format values for display by masking them if encrypted
        at the time of display."""
        if self.is_encrypted(value):
            return mask
        else:
            return value

    def make_random_salt(self, length=12, allowed_chars=('abcdefghijklmnopqrs'
                                                         'tuvwxyzABCDEFGHIJKL'
                                                         'MNOPQRSTUVWXYZ01234'
                                                         '56789!@#%^&*()?<>.,'
                                                         '[]{}')):
        return self.get_random_string(length, allowed_chars)
