from .base_encrypted_field import BaseEncryptedField


class LocalAesEncryptionField(BaseEncryptedField):

    """For encrypting long text """

    def __init__(self, *args, **kwargs):

        self.algorithm = 'aes'
        self.mode = 'local'
        defaults = {'help_text': kwargs.get('help_text', '') + ' (Encryption: {0} {1})'.format(self.algorithm, self.mode,)}
        kwargs.update(defaults)
        super(LocalAesEncryptionField, self).__init__(*args, **kwargs)
