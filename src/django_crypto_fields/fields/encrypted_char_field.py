from .base_rsa_field import BaseRsaField

__all__ = ["EncryptedCharField"]


class EncryptedCharField(BaseRsaField):
    description = "rsa encrypted field for 'CharField'"
