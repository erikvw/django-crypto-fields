class DjangoCryptoFieldsLoadingError(Exception):
    pass


class DjangoCryptoFieldsKeysAlreadyLoaded(Exception):
    pass


class EncryptionError(Exception):
    pass


class CipherError(Exception):
    pass


class AlgorithmError(Exception):
    pass


class ModeError(Exception):
    pass


class EncryptionKeyError(Exception):
    pass


class EncryptionLookupError(Exception):
    pass


class MalformedCiphertextError(Exception):
    pass
