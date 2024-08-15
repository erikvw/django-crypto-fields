from datetime import date, datetime

from django import forms
from django.core.exceptions import ValidationError
from django.db.models.fields import DateTimeCheckMixin, _to_naive
from django.utils.dateparse import parse_date
from django.utils.translation import gettext as _

from ..encoding import DATE_STRING
from .base_rsa_field import BaseRsaField

__all__ = ["EncryptedDateField"]


class EncryptedDateField(DateTimeCheckMixin, BaseRsaField):
    description = "local-rsa encrypted field for 'DateField'"
    default_error_messages = {
        "invalid": _(
            "“%(value)s” value has an invalid date format. It must be " "in YYYY-MM-DD format."
        ),
        "invalid_date": _(
            "“%(value)s” value has the correct format (YYYY-MM-DD) "
            "but it is an invalid date."
        ),
    }

    def __init__(self, auto_now=False, auto_now_add=False, **kwargs):
        self.auto_now, self.auto_now_add = auto_now, auto_now_add
        if auto_now or auto_now_add:
            kwargs["editable"] = False
            kwargs["blank"] = True
        super().__init__(**kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.auto_now:
            kwargs["auto_now"] = True
        if self.auto_now_add:
            kwargs["auto_now_add"] = True
        if self.auto_now or self.auto_now_add:
            del kwargs["editable"]
            del kwargs["blank"]
        return name, path, args, kwargs

    def _check_fix_default_value(self):
        """
        Warn that using an actual date or datetime value is probably wrong;
        it's only evaluated on server startup.
        """
        if not self.has_default():
            return []

        value = self.default
        if isinstance(value, datetime):
            value = _to_naive(value).date()
        elif isinstance(value, date):
            pass
        else:
            return []
        return self._check_if_value_fixed(value)

    def pre_save(self, model_instance, add):
        if self.auto_now or (self.auto_now_add and add):
            value = date.today()
            setattr(model_instance, self.attname, value)
            return value
        else:
            return super().pre_save(model_instance, add)

    def get_prep_value(self, value: date | None) -> str | None:
        if value:
            value = datetime.strftime(value, DATE_STRING)
        return super().get_prep_value(value)

    def to_python(self, value: str | date | None) -> date | None:
        if value is None:
            return value
        if type(value) is date:
            return value
        try:
            parsed = parse_date(value)
            if parsed is not None:
                return parsed
        except ValueError:
            raise ValidationError(
                self.error_messages["invalid_date"],
                code="invalid_date",
                params={"value": value},
            )
        raise ValidationError(
            self.error_messages["invalid"],
            code="invalid",
            params={"value": value},
        )

    def formfield(self, **kwargs):
        kwargs.update(form_class=forms.DateField)
        return super().formfield(**kwargs)
