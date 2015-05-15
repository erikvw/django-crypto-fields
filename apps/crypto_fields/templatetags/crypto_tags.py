from django import template

from ..classes import FieldCryptor
from ..utils import mask_encrypted

register = template.Library()


@register.filter(name='encrypted')
def encrypted(value):
    retval = value
    field_cryptor = FieldCryptor('rsa', 'local')
    if field_cryptor.is_encrypted(value, has_secret=False):
        retval = mask_encrypted(value)
    return retval
