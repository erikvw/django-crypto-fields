from .base_field import BaseField


class BaseRsaField(BaseField):

    def __init__(self, *args, **kwargs):
        algorithm = 'rsa'
        mode = 'local'
        super(BaseRsaField, self).__init__(algorithm, mode, *args, **kwargs)
