from .base_rsa_field import BaseRsaField

__all__ = ["EncryptedIntegerField"]


class EncryptedIntegerField(BaseRsaField):
    description = "local-rsa encrypted field for 'IntegerField'"

    def to_python(self, value):
        """Returns as integer"""
        retval = super().to_python(value)
        retval = int(retval)
        return retval
