from .base_encrypted_field import BaseEncryptedField


class IrreversibleRsaEncryptionField(BaseEncryptedField):

    """   Sames as Restricted except the private key does not exist so values can never be decrypted.. """

    def __init__(self, *args, **kwargs):

        self.algorithm = 'rsa'
        self.mode = 'irreversible'
        defaults = {'help_text': kwargs.get('help_text', '') + ' (Encryption: {0} {1})'.format(self.algorithm, self.mode,)}
        kwargs.update(defaults)
        super(IrreversibleRsaEncryptionField, self).__init__(*args, **kwargs)
