from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Type

from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .constants import CIPHER_PREFIX, ENCODING, HASH_PREFIX
from .exceptions import MalformedCiphertextError

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
    """Return the Crypt model that is active in this project."""
    try:
        return django_apps.get_model(get_crypt_model(), require_ready=False)
    except ValueError:
        raise ImproperlyConfigured(
            "Invalid. `settings.DJANGO_CRYPTO_FIELDS_MODEL` must refer to a model "
            f"using lower_label format. Got {get_crypt_model()}."
        )
    except LookupError:
        raise ImproperlyConfigured(
            "Invalid. `settings.DJANGO_CRYPTO_FIELDS_MODEL` refers to a model "
            f"that has not been installed. Got {get_crypt_model()}."
        )


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


def safe_encode_utf8(value) -> bytes:
    try:
        value = value.encode(ENCODING)
    except AttributeError:
        pass
    return value


def has_valid_hash_or_raise(ciphertext: bytes, hash_size: int) -> bool:
    """Verifies hash segment of ciphertext (bytes) and
    raises an exception if not OK.
    """
    ciphertext = safe_encode_utf8(ciphertext)
    hash_prefix = HASH_PREFIX.encode(ENCODING)
    if ciphertext == HASH_PREFIX.encode(ENCODING):
        raise MalformedCiphertextError(f"Ciphertext has not hash. Got {ciphertext}")
    if not ciphertext[: len(hash_prefix)] == hash_prefix:
        raise MalformedCiphertextError(
            f"Ciphertext must start with {hash_prefix}. "
            f"Got {ciphertext[:len(hash_prefix)]}"
        )
    hash_value = ciphertext[len(hash_prefix) :].split(CIPHER_PREFIX.encode(ENCODING))[0]
    if len(hash_value) != hash_size:
        raise MalformedCiphertextError(
            "Expected hash prefix to be followed by a hash. Got something else or nothing"
        )
    return True


def has_valid_value_or_raise(
    value: str | bytes, hash_size: int, has_secret=None
) -> str | bytes:
    """Encodes the value, validates its format, and returns it
    or raises an exception.

    A value is either a value that can be encrypted or one that
    already is encrypted.

    * A value cannot just be equal to HASH_PREFIX or CIPHER_PREFIX;
    * A value prefixed with HASH_PREFIX must be followed by a
      valid hash (by length);
    * A value prefixed with HASH_PREFIX + hashed_value +
      CIPHER_PREFIX must be followed by some text;
    * A value prefix by CIPHER_PREFIX must be followed by
      some text;
    """
    has_secret = True if has_secret is None else has_secret
    encoded_value = safe_encode_utf8(value)
    if encoded_value is not None and encoded_value != b"":
        if encoded_value in [
            HASH_PREFIX.encode(ENCODING),
            CIPHER_PREFIX.encode(ENCODING),
        ]:
            raise MalformedCiphertextError("Expected a value, got just the encryption prefix.")
        has_valid_hash_or_raise(encoded_value, hash_size)
        if has_secret:
            is_valid_ciphertext_or_raise(encoded_value, hash_size)
    return value  # note, is original passed value


def is_valid_ciphertext_or_raise(ciphertext: bytes, hash_size: int):
    """Returns an unchanged ciphertext after verifying format cipher_prefix +
    hash + cipher_prefix + secret.
    """
    try:
        ciphertext.split(HASH_PREFIX.encode(ENCODING))[1]
    except IndexError:
        raise MalformedCiphertextError(
            f"Malformed ciphertext. Expected prefixes {HASH_PREFIX}"
        )
    try:
        ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[1]
    except IndexError:
        raise MalformedCiphertextError(
            f"Malformed ciphertext. Expected prefixes {CIPHER_PREFIX}"
        )
    try:
        if ciphertext[: len(HASH_PREFIX)] != HASH_PREFIX.encode(ENCODING):
            raise MalformedCiphertextError(
                f"Malformed ciphertext. Expected hash prefix {HASH_PREFIX}"
            )
        if (
            len(
                ciphertext.split(HASH_PREFIX.encode(ENCODING))[1].split(
                    CIPHER_PREFIX.encode(ENCODING)
                )[0]
            )
            != hash_size
        ):
            raise MalformedCiphertextError(
                f"Malformed ciphertext. Expected hash size of {hash_size}."
            )
    except IndexError:
        MalformedCiphertextError("Malformed ciphertext.")
    return ciphertext
