from .base_encrypted_field import BaseEncryptedField


class RestrictedRsaEncryptionField(BaseEncryptedField):

    def __init__(self, *args, **kwargs):
        self.algorithm = 'rsa'
        self.mode = 'restricted'
        defaults = {'help_text': kwargs.get('help_text', '') + ' (Encryption: {0} {1})'.format(self.algorithm, self.mode,)}
        kwargs.update(defaults)
        super(RestrictedRsaEncryptionField, self).__init__(*args, **kwargs)
