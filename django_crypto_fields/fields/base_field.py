from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.core.management.color import color_style
from django.db import models
from django.forms import widgets

from ..constants import ENCODING, HASH_PREFIX, LOCAL_MODE, RSA
from ..exceptions import (
    DjangoCryptoFieldsKeysNotLoaded,
    EncryptionError,
    EncryptionLookupError,
)
from ..field_cryptor import FieldCryptor
from ..keys import encryption_keys

if TYPE_CHECKING:
    from ..keys import Keys

style = color_style()


class BaseField(models.Field):
    description = "Field class that stores values as encrypted"

    def __init__(self, algorithm: str, access_mode: str, *args, **kwargs):
        self.readonly = False
        self.keys: Keys = encryption_keys
        if not encryption_keys.loaded:
            raise DjangoCryptoFieldsKeysNotLoaded(
                "Encryption keys not loaded. You need to run initialize()"
            )
        self.algorithm = algorithm or RSA
        self.mode = access_mode or LOCAL_MODE
        self.help_text: str = kwargs.get("help_text", "")
        if not self.help_text.startswith(" (Encryption:"):
            self.help_text = "{} (Encryption: {} {})".format(
                self.help_text.split(" (Encryption:")[0], algorithm.upper(), self.mode
            )
        self.field_cryptor = FieldCryptor(self.algorithm, self.mode)
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

    def deconstruct(self):
        name, path, args, kwargs = super(BaseField, self).deconstruct()
        kwargs["help_text"] = self.help_text
        kwargs["max_length"] = self.max_length
        return name, path, args, kwargs

    def formfield(self, **kwargs):
        defaults = kwargs
        try:
            show_encrypted_values = settings.SHOW_CRYPTO_FORM_DATA
        except AttributeError:
            show_encrypted_values = True
        if not show_encrypted_values:
            defaults = {"disabled": True, "widget": widgets.PasswordInput}
            defaults.update(kwargs)
        return super(BaseField, self).formfield(**defaults)

    def decrypt(self, value):
        if value is None or value in ["", b""]:
            decrypted_value = value
        else:
            decrypted_value = self.field_cryptor.decrypt(value)
        return decrypted_value

    def from_db_value(self, value, *args):
        if value is None or value in ["", b""]:
            return value
        return self.decrypt(value)

    def get_prep_value(self, value):
        """Returns the encrypted value, including prefix, as the
        query value (to query the db).

        db is queried using the hash

        Note: partial matches do not work. See get_prep_lookup().
        """
        return self.field_cryptor.get_prep_value(value)

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
                value = HASH_PREFIX.encode(ENCODING) + self.field_cryptor.hash(value)
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
            hashed_values.append(HASH_PREFIX.encode(ENCODING) + self.field_cryptor.hash(value))
        return hashed_values

    def get_internal_type(self):
        """This is a `CharField` as we only ever store the hash,
        which is a fixed length char.
        """
        return "CharField"

    def mask(self, value, mask=None):
        return self.field_cryptor.mask(value, mask)
