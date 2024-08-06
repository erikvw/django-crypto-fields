from __future__ import annotations

import binascii
import hashlib
import sys
from datetime import date, datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Type

from django.apps import apps as django_apps
from django.conf import settings

from .constants import HASH_ALGORITHM, HASH_ROUNDS
from .encoding import safe_encode_date
from .exceptions import DjangoCryptoFieldsError, EncryptionError

if TYPE_CHECKING:
    from django.db import models

    from .fields import BaseField
    from .models import Crypt

    class AnyModel(models.Model):
        class Meta:
            verbose_name = "Any Model"


def has_encrypted_fields(model: AnyModel) -> bool:
    for field in model._meta.get_fields():
        if hasattr(field, "field_cryptor"):
            return True
    return False


def get_encrypted_fields(model: models.Model) -> list[BaseField]:
    encrypted_fields = []
    for field in model._meta.get_fields():
        if hasattr(field, "field_cryptor"):
            encrypted_fields.append(field)
    return encrypted_fields


def get_crypt_model() -> str:
    return getattr(settings, "DJANGO_CRYPTO_FIELDS_MODEL", "django_crypto_fields.crypt")


def get_crypt_model_cls() -> Type[Crypt]:
    return django_apps.get_model(get_crypt_model())


def get_auto_create_keys_from_settings() -> bool:
    auto_create_keys = getattr(
        settings,
        "DJANGO_CRYPTO_FIELDS_AUTO_CREATE",
        getattr(settings, "AUTO_CREATE_KEYS", None),
    )
    if "runtests.py" in sys.argv:
        if auto_create_keys is None:
            auto_create_keys = True
    return auto_create_keys


def get_keypath_from_settings() -> str:
    return getattr(
        settings, "DJANGO_CRYPTO_FIELDS_KEY_PATH", getattr(settings, "KEY_PATH", None)
    )


def get_test_module_from_settings() -> str:
    return getattr(settings, "DJANGO_CRYPTO_FIELDS_TEST_MODULE", "runtests.py")


def get_key_prefix_from_settings() -> str:
    return getattr(settings, "DJANGO_CRYPTO_FIELDS_KEY_PREFIX", "user")


def make_hash(
    value: str | date | datetime | int | float | Decimal, salt_key: bytes
) -> bytes | None:
    """Returns a hexified hash of a plaintext value (as bytes).

    The hashed value is used as a signature of the "secret".
    """
    if value is None:
        raise DjangoCryptoFieldsError("Cannot hash None value")
    else:
        if type(value) in [date, datetime]:
            encoded_value = safe_encode_date(value)
        else:
            encoded_value = value.encode()
        dk: bytes = hashlib.pbkdf2_hmac(HASH_ALGORITHM, encoded_value, salt_key, HASH_ROUNDS)
    return binascii.hexlify(dk)


def remove_padding(encoded_value: bytes) -> bytes:
    """Return original bytes value without padding.

    value: a decrypted bytes value with padding

    Length of padding is stored in last two characters of
    value.
    """
    try:
        padding_length = int(binascii.b2a_hex(encoded_value[-1:]))
    except ValueError:
        pass
    else:
        if not padding_length:
            encoded_value = encoded_value[:-1]
        else:
            encoded_value = encoded_value[:-padding_length]
    return encoded_value


def append_padding(encoded_value: bytes, block_size: int) -> bytes:
    """Return an encoded string padded so length is a multiple of
    the block size.

    * store length of padding as the last hex value.
    * if padding is 0, pad as if padding is 16.
    """
    padding_length = (block_size - len(encoded_value) % block_size) % block_size
    padding_length = padding_length or 16
    encoded_value = (
        encoded_value
        + (b"\x00" * (padding_length - 1))
        + binascii.a2b_hex(str(padding_length).zfill(2))
    )
    if len(encoded_value) % block_size > 0:
        multiple = len(encoded_value) / block_size
        raise EncryptionError(
            f"Padding error, got padded string not a multiple "
            f"of {block_size}. Got {multiple}"
        )
    return encoded_value
