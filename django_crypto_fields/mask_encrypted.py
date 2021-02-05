from .constants import LOCAL_MODE, RSA
from .field_cryptor import FieldCryptor


def mask_encrypted(value):
    return FieldCryptor(RSA, LOCAL_MODE).mask(value)
