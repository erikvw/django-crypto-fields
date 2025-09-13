class DjangoCryptoFieldsKeyError(Exception):
    pass


class DjangoCryptoFieldsKeyAlreadyExist(Exception):  # noqa: N818
    pass


class DjangoCryptoFieldsKeysAlreadyLoaded(Exception):  # noqa: N818
    pass


class DjangoCryptoFieldsKeysNotLoaded(Exception):  # noqa: N818
    pass


class DjangoCryptoFieldsError(Exception):
    pass


class DjangoCryptoFieldsKeysDoNotExist(Exception):  # noqa: N818
    pass


class DjangoCryptoFieldsKeyPathError(Exception):
    pass


class DjangoCryptoFieldsKeyPathChangeError(Exception):
    pass


class DjangoCryptoFieldsKeyPathDoesNotExist(Exception):  # noqa: N818
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


class InvalidEncryptionAlgorithm(Exception):  # noqa: N818
    pass
