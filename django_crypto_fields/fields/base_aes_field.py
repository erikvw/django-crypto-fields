from .base_field import BaseField


class BaseAesField(BaseField):

    def __init__(self, *args, **kwargs):
        algorithm = 'aes'
        mode = 'local'
        super(BaseAesField, self).__init__(algorithm, mode, *args, **kwargs)
