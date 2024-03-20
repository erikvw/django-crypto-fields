from __future__ import annotations

import binascii
import hashlib
import sys
from typing import TYPE_CHECKING, Type

from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .constants import CIPHER_PREFIX, ENCODING, HASH_ALGORITHM, HASH_PREFIX, HASH_ROUNDS
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


def safe_decode(value) -> bytes:
    try:
        value.decode()
    except AttributeError:
        pass
    return value


def has_valid_hash_or_raise(ciphertext: bytes, hash_size: int) -> bool:
    """Verifies hash segment of ciphertext (bytes) and
    raises an exception if not OK.
    """
    ciphertext = safe_encode_utf8(ciphertext)
    hash_value = ciphertext[len(safe_encode_utf8(HASH_PREFIX)) :].split(
        safe_encode_utf8(CIPHER_PREFIX)
    )[0]
    if len(hash_value) != hash_size:
        raise MalformedCiphertextError(
            "Expected hash prefix to be followed by a hash. Got something else or nothing"
        )
    return True


def make_hash(value, salt_key) -> bytes:
    """Returns a hexified hash of a plaintext value (as bytes).

    The hashed value is used as a signature of the "secret".
    """
    encoded_value = safe_encode_utf8(value)
    dk = hashlib.pbkdf2_hmac(HASH_ALGORITHM, encoded_value, salt_key, HASH_ROUNDS)
    return binascii.hexlify(dk)
