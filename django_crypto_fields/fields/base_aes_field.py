from ..constants import AES, LOCAL_MODE
from .base_field import BaseField


class BaseAesField(BaseField):
    def __init__(self, *args, **kwargs):
        algorithm = AES
        mode = LOCAL_MODE
        super(BaseAesField, self).__init__(algorithm, mode, *args, **kwargs)
