from gettext import gettext as _

from django.core.exceptions import ValidationError

from .base_rsa_field import BaseRsaField

__all__ = ["EncryptedIntegerField"]

INVALID_VALUE = _("Invalid value. Expected a whole number (integer)")


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
        except ValueError as e:
            raise ValidationError(
                INVALID_VALUE, code="invalid", params={"value": value}
            ) from e
        return value
