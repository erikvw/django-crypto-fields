class DjangoCryptoFieldsKeyError(Exception):
    pass


class DjangoCryptoFieldsKeyAlreadyExist(Exception):
    pass


class DjangoCryptoFieldsKeysAlreadyLoaded(Exception):
    pass


class DjangoCryptoFieldsKeysNotLoaded(Exception):
    pass


class DjangoCryptoFieldsError(Exception):
    pass


class DjangoCryptoFieldsKeysDoNotExist(Exception):
    pass


class DjangoCryptoFieldsKeyPathError(Exception):
    pass


class DjangoCryptoFieldsKeyPathChangeError(Exception):
    pass


class DjangoCryptoFieldsKeyPathDoesNotExist(Exception):
    pass


class DjangoCryptoFieldsEncodingError(Exception):
    pass


class DjangoCryptoFieldsDecodingError(Exception):
    pass


class EncryptionError(Exception):
    pass


class CipherError(Exception):
    pass


class EncryptionKeyError(Exception):
    pass


class EncryptionLookupError(Exception):
    pass


class MalformedCiphertextError(Exception):
    pass


class InvalidEncryptionAlgorithm(Exception):
    pass
