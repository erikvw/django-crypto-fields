from ..classes import FieldCryptor


def mask_encrypted(value, mask=None):
    field_cryptor = FieldCryptor()
    return field_cryptor.mask(value, mask)
