import socket

from django.db.models import CharField
from django.utils.translation import ugettext as _

from django_extensions.db.fields import UUIDField as DJEX_UUIDField


class UUIDAutoFieldError(Exception):
    pass


class UUIDAutoField(DJEX_UUIDField):
    """
    This is not technically an AutoField as the DB does not
    provide the value. A django AutoField lets the DB provide
    the value in base.py (save_base). To avoid that happening here,
    this field inherits from UUIDField->CharField->Field instead
    of AutoField->Field.

    """
    description = _("UuidAutoField")

    def __init__(self, *args, **kwargs):
        try:
            assert kwargs.get('primary_key', False) is True
        except AssertionError:
            raise UUIDAutoFieldError(
                f"{self.__class__.__name__} must have primary_key=True.")
        super(UUIDAutoField, self).__init__(*args, **kwargs)


class HostnameCreationField (CharField):
    """
    HostnameCreationField

    By default, sets editable=False, blank=True, default=socket.gethostname()
    """

    description = _("Custom field for hostname created")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('editable', False)
        kwargs.setdefault('blank', True)
        kwargs.setdefault('max_length', 50)
        kwargs.setdefault('verbose_name', 'Hostname')
        kwargs.setdefault('default', socket.gethostname())
        CharField.__init__(self, *args, **kwargs)

    def get_internal_type(self):
        return "CharField"


class HostnameModificationField (CharField):
    """
    HostnameModificationField

    By default, sets editable=False, blank=True, default=socket.gethostname()

    Sets value to socket.gethostname() on each save of the model.
    """
    description = _("Custom field for hostname modified")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('editable', False)
        kwargs.setdefault('blank', True)
        kwargs.setdefault('max_length', 50)
        kwargs.setdefault('verbose_name', 'Hostname')
        kwargs.setdefault('default', socket.gethostname())
        CharField.__init__(self, *args, **kwargs)

    def pre_save(self, model, add):
        value = socket.gethostname()
        setattr(model, self.attname, value)
        return value

    def get_internal_type(self):
        return "CharField"
