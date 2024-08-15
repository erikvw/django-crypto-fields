from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.db import models
from django.forms import widgets

from ..constants import HASH_PREFIX, LOCAL_MODE, RSA
from ..exceptions import (
    DjangoCryptoFieldsKeysNotLoaded,
    EncryptionError,
    EncryptionLookupError,
)
from ..field_cryptor import FieldCryptor
from ..keys import encryption_keys

if TYPE_CHECKING:
    from ..keys import Keys

__all__ = ["BaseField"]


class BaseField(models.Field):
    description = "Field class that stores values as encrypted"

    def __init__(self, algorithm: str, access_mode: str, *args, **kwargs):
        self._field_cryptor = None
        self._keys = None
        self.readonly = False
        self.algorithm = algorithm or RSA
        self.mode = access_mode or LOCAL_MODE

        self.help_text: str = kwargs.get("help_text", "")
        if not self.help_text.startswith(" (Encryption:"):
            self.help_text = "{} (Encryption: {} {})".format(
                self.help_text.split(" (Encryption:")[0], algorithm.upper(), self.mode
            )

        min_length: int = len(HASH_PREFIX) + self.field_cryptor.hash_size
        max_length: int = kwargs.get("max_length", min_length)
        self.max_length: int = min_length if max_length < min_length else max_length
        if self.algorithm == RSA:
            max_message_length: int = self.keys.rsa_key_info[self.mode]["max_message_length"]
            if self.max_length > max_message_length:
                raise EncryptionError(
                    "{} attribute 'max_length' cannot exceed {} for RSA. Got {}. "
                    "Try setting 'algorithm' = 'aes'.".format(
                        self.__class__.__name__, max_message_length, self.max_length
                    )
                )

        kwargs["max_length"] = self.max_length
        kwargs["help_text"] = self.help_text
        kwargs.setdefault("blank", True)

        super().__init__(*args, **kwargs)

    @property
    def keys(self) -> Keys:
        if not self._keys:
            if not encryption_keys.loaded:
                raise DjangoCryptoFieldsKeysNotLoaded(
                    "Encryption keys not loaded. You need to run initialize()"
                )
            self._keys = encryption_keys
        return self._keys

    @property
    def field_cryptor(self) -> FieldCryptor:
        if not self._field_cryptor:
            self._field_cryptor = FieldCryptor(self.algorithm, self.mode)
        return self._field_cryptor

    def get_internal_type(self):
        """This is a `CharField` as we only ever store the
        hash_prefix + hash, which is a fixed length char.
        """
        return "CharField"

    def deconstruct(self):
        name, path, args, kwargs = super(BaseField, self).deconstruct()
        kwargs["help_text"] = self.help_text
        kwargs["max_length"] = self.max_length
        return name, path, args, kwargs

    def formfield(self, **kwargs):
        if not getattr(settings, "SHOW_CRYPTO_FORM_DATA", True):
            kwargs.update({"disabled": True, "widget": widgets.PasswordInput})
        return super().formfield(**kwargs)

    def from_db_value(self, value: str | None, *args) -> str | None:
        """Returns the decrypted value, an empty string, or None."""
        value = value.encode() if value is not None else value
        if value == b"":
            return ""
        return self.field_cryptor.decrypt(value) if value is not None else None

    def get_prep_value(self, value: str | None) -> str | None:
        """Returns prefix + hash_value, an empty string, or None
        for use as a parameter in a query or for saving into
        the database.

        Note: partial matches do not work. See get_prep_lookup().
        """
        value = self.field_cryptor.get_prep_value(value)
        return super().get_prep_value(value)

    def get_prep_lookup(self, lookup_type, value):
        """Convert the value to a hash with prefix and pass to super.

        Since the available value is the hash, only exact match
        lookup types are supported.
        """
        # TODO: why value in ["", b""] and not just value == b""
        if value is None or value in ["", b""]:
            pass
        else:
            self.raise_if_unsupported_lookup(lookup_type)
            if lookup_type == "isnull":
                value = self.get_isnull_as_lookup(value)
            elif lookup_type == "in":
                value = self.get_in_as_lookup(value)
            else:
                value = HASH_PREFIX.encode() + self.field_cryptor.hash(value)
        return super().get_prep_lookup(lookup_type, value)

    @staticmethod
    def raise_if_unsupported_lookup(lookup_type):
        supported_lookups = ["iexact", "exact", "in", "isnull"]
        if lookup_type not in supported_lookups:
            raise EncryptionLookupError(
                f"Field type only supports supports '{supported_lookups}' "
                f"lookups. Got '{lookup_type}'"
            )

    def get_isnull_as_lookup(self, value):
        return value

    def get_in_as_lookup(self, values):
        hashed_values = []
        for value in values:
            hashed_values.append(HASH_PREFIX.encode() + self.field_cryptor.hash(value))
        return hashed_values

    def mask(self, value, mask=None):
        return self.field_cryptor.mask(value, mask)
