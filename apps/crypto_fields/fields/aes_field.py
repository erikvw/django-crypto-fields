from apps.crypto_fields.fields.base_field import BaseEncryptedField


class AesField(BaseEncryptedField):
    def __init__(self, *args, **kwargs):
        kwargs['algorithm'] = 'aes'
        kwargs['mode'] = kwargs.get('mode', 'local')
        kwargs['help_text'] = kwargs.get('help_text', '') + ' (Encryption: AES {})'.format(kwargs['mode'])
        super(AesField, self).__init__(*args, **kwargs)
