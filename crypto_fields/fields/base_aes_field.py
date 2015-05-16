from .base_field import BaseField


class BaseAesField(BaseField):
    def __init__(self, *args, **kwargs):
        kwargs['algorithm'] = 'aes'
        kwargs['mode'] = kwargs.get('mode', 'local')
        kwargs['help_text'] = kwargs.get('help_text', '') + ' (Encryption: AES {})'.format(kwargs['mode'])
        super(BaseAesField, self).__init__(*args, **kwargs)
