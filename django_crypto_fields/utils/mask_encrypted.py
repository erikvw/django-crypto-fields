from ..classes import FieldCryptor


def mask_encrypted(value):
    return FieldCryptor('rsa', 'local').mask(value)
