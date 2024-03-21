from decimal import Decimal

from .base_rsa_field import BaseRsaField

__all__ = ["EncryptedDecimalField"]


class EncryptedDecimalField(BaseRsaField):
    description = "local-rsa encrypted field for 'IntegerField'"

    def __init__(self, *args, **kwargs):
        self.validate_max_digits(kwargs)
        self.validate_decimal_places(kwargs)
        decimal_decimal_places = int(kwargs.get("decimal_places"))
        decimal_max_digits = int(kwargs.get("max_digits"))
        del kwargs["decimal_places"]
        del kwargs["max_digits"]
        super().__init__(*args, **kwargs)
        self.decimal_decimal_places = decimal_decimal_places
        self.decimal_max_digits = decimal_max_digits

    def to_string(self, value):
        if isinstance(value, (str,)):
            raise TypeError("Expected basestring. Got {0}".format(value))
        return str(value)

    def to_python(self, value):
        """Returns as integer"""
        retval = super(EncryptedDecimalField, self).to_python(value)
        if retval:
            if not self.field_cryptor.is_encrypted(retval):
                retval = Decimal(retval).to_eng_string()
        return retval

    @staticmethod
    def validate_max_digits(kwargs):
        if "max_digits" not in kwargs:
            raise AttributeError(
                "EncryptedDecimalField requires attribute 'max_digits. " "Got none"
            )
        elif "max_digits" in kwargs:
            try:
                int(kwargs.get("max_digits"))
            except (TypeError, ValueError):
                raise ValueError(
                    f"EncryptedDecimalField attribute 'max_digits must be an "
                    f'integer. Got {kwargs.get("max_digits")}'
                )

    @staticmethod
    def validate_decimal_places(kwargs):
        if "decimal_places" not in kwargs:
            raise AttributeError(
                "EncryptedDecimalField requires attribute 'decimal_places. " "Got none"
            )
        elif "decimal_places" in kwargs:
            try:
                int(kwargs.get("decimal_places"))
            except (TypeError, ValueError):
                raise ValueError(
                    f"EncryptedDecimalField attribute 'decimal_places must be an "
                    f'integer. Got {kwargs.get("decimal_places")}'
                )
