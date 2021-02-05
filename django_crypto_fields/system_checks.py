import os
import sys
from collections import namedtuple

from Crypto.Cipher import AES
from django.apps import apps as django_apps
from django.conf import settings
from django.core.checks import Critical, Error

from .cryptor import Cryptor
from .persist_key_path import (
    DjangoCryptoFieldsKeyPathChangeError,
    DjangoCryptoFieldsKeyPathError,
    persist_key_path,
)

err = namedtuple("Err", "id cls")

error_configs = dict(
    key_path_check=err("django_crypto_fields.C001", Critical),
    encryption_keys_check=err("django_crypto_fields.E001", Error),
    aes_mode_check=err("django_crypto_fields.E002", Error),
)


def testing():
    if "test" in sys.argv:
        return True
    if "runtests" in sys.argv:
        return True
    return False


def key_path_check(app_configs, **kwargs):
    errors = []
    if not settings.DEBUG:
        app_config = django_apps.get_app_config("django_crypto_fields")
        key_path = app_config.key_path
        error = error_configs.get("key_path_check")
        check_failed = False
        filename = os.path.join(settings.ETC_DIR, "django_crypto_fields")
        hint = f"settings.KEY_PATH does not match the path stored in {filename}."
        try:
            persist_key_path(key_path=key_path, filename=filename)
        except (
            DjangoCryptoFieldsKeyPathChangeError,
            DjangoCryptoFieldsKeyPathError,
        ) as e:
            error_msg = str(e)
            check_failed = True
        if check_failed:
            errors.append(error.cls(error_msg, hint=hint, obj=None, id=error.id))
    return errors


def encryption_keys_check(app_configs, **kwargs):
    app_config = django_apps.get_app_config("django_crypto_fields")
    key_files = app_config.key_files
    errors = []
    check_failed = None
    try:
        auto_create_keys = settings.AUTO_CREATE_KEYS
    except AttributeError:
        auto_create_keys = None
    if key_files.key_files_exist and auto_create_keys and not testing():
        error = error_configs.get("encryption_keys_check")
        error_msg = (
            "settings.AUTO_CREATE_KEYS may not be 'True' when encryption keys exist."
        )
        hint = (
            "Did you backup your keys? Perhaps you just created new keys, "
            "to continue, set AUTO_CREATE_KEYS=False and restart."
        )
        check_failed = True
    if check_failed:
        errors.append(error.cls(error_msg, hint=hint, obj=None, id=error.id))
    return errors


def aes_mode_check(app_configs, **kwargs):
    error = error_configs.get("aes_mode_check")
    errors = []
    hint = (
        "See django_crypto_fields.cryptor.py and comments " "in pycrypto.blockalgo.py."
    )
    cryptor = Cryptor()
    if cryptor.aes_encryption_mode == AES.MODE_CFB:
        error_msg = "Encryption mode MODE_CFB should not be used."
        errors.append(error.cls(error_msg, hint=hint, obj=None, id=error.id))
    return errors
