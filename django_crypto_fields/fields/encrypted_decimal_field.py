from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError

from .base_rsa_field import BaseRsaField

__all__ = ["EncryptedDecimalField"]


class EncryptedDecimalField(BaseRsaField):
    description = "local-rsa encrypted field for 'IntegerField'"

    def __init__(self, *args, max_digits=None, decimal_places=None, **kwargs):
        self.decimal_places = int(decimal_places or 2)
        self.max_digits = int(max_digits or 8)
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        kwargs["decimal_places"] = self.decimal_places
        kwargs["max_digits"] = self.max_digits
        return name, path, args, kwargs

    def get_prep_value(self, value: Decimal | None) -> str | None:
        if value is not None:
            value = str(value)
        return super().get_prep_value(value)

    def to_python(self, value: str | Decimal | None) -> Decimal | None:
        if value is None:
            return value
        if isinstance(value, Decimal):
            return value
        try:
            value = Decimal(value)
        except InvalidOperation:
            raise ValidationError(
                "Invalid value. Expected a decimal",
                code="invalid",
                params={"value": value},
            )
        return value
