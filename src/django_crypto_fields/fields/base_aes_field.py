from ..constants import AES, LOCAL_MODE
from .base_field import BaseField

__all__ = ["BaseAesField"]


class BaseAesField(BaseField):
    def __init__(self, *args, **kwargs):
        algorithm = AES
        access_mode = LOCAL_MODE
        super().__init__(algorithm, access_mode, *args, **kwargs)
