from django.core.exceptions import ValidationError

from .base_rsa_field import BaseRsaField

__all__ = ["EncryptedIntegerField"]


class EncryptedIntegerField(BaseRsaField):
    description = "local-rsa encrypted field for 'IntegerField'"

    def get_prep_value(self, value: int | None) -> str | None:
        if value is not None:
            value = str(value)
        return super().get_prep_value(value)

    def to_python(self, value: str | int | None) -> int | None:
        if value is None:
            return value
        if isinstance(value, int):
            return value
        try:
            value = int(value)
        except ValueError:
            raise ValidationError(
                "Invalid value. Expected a whole number (integer)",
                code="invalid",
                params={"value": value},
            )
        return value
