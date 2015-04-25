from ..classes import BaseCryptor


def mask_encrypted(value):
    base_cryptor = BaseCryptor()
    return base_cryptor.mask(value)
