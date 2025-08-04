from datetime import date, datetime

from django import forms
from django.core.exceptions import ValidationError
from django.db.models.fields import DateTimeCheckMixin
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.utils.translation import gettext as _

from ..encoding import DATETIME_STRING
from .base_rsa_field import BaseRsaField

__all__ = ["EncryptedDateTimeField"]


class EncryptedDateTimeField(DateTimeCheckMixin, BaseRsaField):
    description = "local-rsa encrypted field for 'DateTimeField'"
    default_error_messages = {
        "invalid": _(
            "“%(value)s” value has an invalid format. It must be in "
            "YYYY-MM-DD HH:MM[:ss[.uuuuuu]][TZ] format."
        ),
        "invalid_date": _(
            "“%(value)s” value has the correct format "
            "(YYYY-MM-DD) but it is an invalid date."
        ),
        "invalid_datetime": _(
            "“%(value)s” value has the correct format "
            "(YYYY-MM-DD HH:MM[:ss[.uuuuuu]][TZ]) "
            "but it is an invalid date/time."
        ),
    }

    def __init__(self, auto_now=False, auto_now_add=False, **kwargs):
        self.auto_now, self.auto_now_add = auto_now, auto_now_add
        if auto_now or auto_now_add:
            kwargs["editable"] = False
            kwargs["blank"] = True
        super().__init__(**kwargs)

    def _check_fix_default_value(self):
        """
        Warn that using an actual date or datetime value is probably wrong;
        it's only evaluated on server startup.
        """
        if not self.has_default():
            return []

        value = self.default
        if isinstance(value, (datetime, date)):
            return self._check_if_value_fixed(value)
        return []

    def from_db_value(self, value: str | None, *args) -> datetime | None:
        """Returns the decrypted value, an empty string, or None."""
        if value is None:
            return None
        date_string = self.field_cryptor.decrypt(value.encode())
        if not date_string:
            return None
        return datetime.strptime(date_string, DATETIME_STRING)

    def get_prep_value(self, value: date | None) -> str | None:
        if value:
            value = datetime.strftime(value, DATETIME_STRING)
        return super().get_prep_value(value)

    def to_python(self, value: str | datetime | None) -> date | None:
        if value is None:
            return value
        if type(value) is datetime:
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

    def pre_save(self, model_instance, add):
        if self.auto_now or (self.auto_now_add and add):
            value = timezone.now()
            setattr(model_instance, self.attname, value)
            return value
        else:
            return super().pre_save(model_instance, add)

    def formfield(self, **kwargs):
        kwargs.update(form_class=forms.SplitDateTimeField)
        return super().formfield(**kwargs)
