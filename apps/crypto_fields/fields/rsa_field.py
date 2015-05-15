from .base_encrypted_field import BaseEncryptedField


class RsaField(BaseEncryptedField):

    def __init__(self, *args, **kwargs):
        kwargs['algorithm'] = 'rsa'
        kwargs['mode'] = kwargs.get('mode', 'local')
        kwargs['help_text'] = kwargs.get('help_text', '') + ' (Encryption: RSA {})'.format(kwargs['mode'])
        super(RsaField, self).__init__(*args, **kwargs)
