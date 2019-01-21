from ..constants import RSA, LOCAL_MODE
from .base_field import BaseField


class BaseRsaField(BaseField):
    def __init__(self, *args, **kwargs):
        algorithm = RSA
        mode = LOCAL_MODE
        super(BaseRsaField, self).__init__(algorithm, mode, *args, **kwargs)
