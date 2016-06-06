from .field_cryptor import FieldCryptor
from django_crypto_fields.constants import RSA, LOCAL_MODE


def mask_encrypted(value):
    return FieldCryptor(RSA, LOCAL_MODE).mask(value)
