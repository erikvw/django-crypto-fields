from .base_field import BaseField


class BaseRsaField(BaseField):

    def __init__(self, *args, **kwargs):
        kwargs['algorithm'] = 'rsa'
        kwargs['mode'] = kwargs.get('mode', 'local')
        kwargs['help_text'] = kwargs.get('help_text', '') + ' (Encryption: RSA {})'.format(kwargs['mode'])
        super(BaseRsaField, self).__init__(*args, **kwargs)
