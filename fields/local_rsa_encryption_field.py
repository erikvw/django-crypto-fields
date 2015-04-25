from .base_encrypted_field import BaseEncryptedField


class LocalRsaEncryptionField(BaseEncryptedField):

    """  """

    def __init__(self, *args, **kwargs):

        self.algorithm = 'rsa'
        self.mode = 'local'
        defaults = {'help_text': kwargs.get('help_text', '') + ' (Encryption: {0} {1})'.format(self.algorithm, self.mode,)}
        kwargs.update(defaults)
        super(LocalRsaEncryptionField, self).__init__(*args, **kwargs)
