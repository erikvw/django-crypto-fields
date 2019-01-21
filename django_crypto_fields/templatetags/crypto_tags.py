from django import template

from ..field_cryptor import FieldCryptor

register = template.Library()


@register.filter(name="encrypted")
def encrypted(value):
    retval = value
    field_cryptor = FieldCryptor("rsa", "local")
    if field_cryptor.is_encrypted(value, has_secret=False):
        retval = field_cryptor.mask(value)
    return retval
