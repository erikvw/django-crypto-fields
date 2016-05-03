from .fields import BaseField


class CryptoMixin(object):

    @classmethod
    def encrypted_fields(cls):
        return [fld.name for fld in cls._meta.fields if isinstance(fld, BaseField)]
