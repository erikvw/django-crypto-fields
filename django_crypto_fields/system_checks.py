import os

from Crypto.Cipher import AES
from collections import namedtuple
from django.conf import settings
from django.core.checks import Critical, Error
from django_crypto_fields.key_files import KeyFiles

from .cryptor import Cryptor
from .persist_key_path import persist_key_path, DjangoCryptoFieldsKeyPathChangeError

err = namedtuple('Err', 'id cls')

error_configs = dict(
    key_path_check=err('django_crypto_fields.C001', Critical),
    encryption_keys_check_error=('django_crypto_fields.E001', Error),
    aes_mode_check=err('django_crypto_fields.E002', Error),
)


def key_path_check(app_configs, **kwargs):
    error = error_configs.get('key_path_check')
    errors = []
    check_failed = False
    key_path = settings.KEY_PATH
    filename = os.path.join(settings.ETC_DIR, 'django_crypto_fields')
    hint = f'settings.KEY_PATH and the path stored in {filename} are not the same.'
    try:
        persist_key_path(key_path=key_path, filename=filename)
    except DjangoCryptoFieldsKeyPathChangeError as e:
        error_msg = str(e)
        check_failed = True

    if check_failed:
        errors.append(
            error.cls(
                error_msg,
                hint=hint,
                obj=None,
                id=error.id,
            )
        )
    return errors


def encryption_keys_check(app_configs, auto_create_keys=None, **kwargs):
    errors = []
    check_failed = None
    key_files = KeyFiles()
    if not key_files.key_files_exist:
        if auto_create_keys:
            pass
        else:
            error = error_configs.get('encryption_keys_check')
            error_msg = (
                'Failed to find any encryption keys. Confirm that settings.KEY_PATH '
                'points to the correct folder. Loading the wrong encryption keys '
                'can corrupt sensitive data. If this is your first time loading '
                'the project, new keys will be generated and placed in the '
                'settings.KEY_PATH folder.')
            check_failed = True
    if check_failed:
        errors.append(
            error.cls(
                error_msg,
                hint=None,
                obj=None,
                id=error.id,
            )
        )
    return errors


def aes_mode_check(app_configs, **kwargs):
    error = error_configs.get('aes_mode_check')
    errors = []
    hint = ('See django_crypto_fields.cryptor.py and comments '
            'in pycrypto.blockalgo.py.')
    cryptor = Cryptor()
    if cryptor.aes_encryption_mode == AES.MODE_CFB:
        error_msg = (
            'Encryption mode MODE_CFB should not be used.')
        errors.append(
            error.cls(
                error_msg,
                hint=hint,
                obj=None,
                id=error.id,
            )
        )
    return errors
