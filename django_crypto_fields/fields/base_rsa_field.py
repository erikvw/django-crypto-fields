from ..constants import LOCAL_MODE, RSA
from .base_field import BaseField

__all__ = ["BaseRsaField"]


class BaseRsaField(BaseField):
    def __init__(self, *args, **kwargs):
        algorithm = RSA
        access_mode = LOCAL_MODE
        super().__init__(algorithm, access_mode, *args, **kwargs)
