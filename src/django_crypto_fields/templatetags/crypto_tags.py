from django import template

from ..constants import LOCAL_MODE, RSA
from ..field_cryptor import FieldCryptor

register = template.Library()


@register.filter(name="encrypted")
def encrypted(value: str):
    field_cryptor = FieldCryptor(RSA, LOCAL_MODE)
    return field_cryptor.mask(value)
