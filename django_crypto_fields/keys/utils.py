from __future__ import annotations

import sys
from pathlib import PurePath

from django_crypto_fields.constants import (
    AES,
    LOCAL_MODE,
    PRIVATE,
    PUBLIC,
    RESTRICTED_MODE,
    RSA,
    SALT,
)


def get_template(path: PurePath, key_prefix: str) -> dict[str, dict[str, dict[str, PurePath]]]:
    """Returns the data structure to store encryption keys.

    The Keys class will replace the filenames with the actual keys.
    """
    return {
        RSA: {
            RESTRICTED_MODE: {
                PUBLIC: path / (key_prefix + "-rsa-restricted-public.pem"),
                PRIVATE: path / (key_prefix + "-rsa-restricted-private.pem"),
            },
            LOCAL_MODE: {
                PUBLIC: path / (key_prefix + "-rsa-local-public.pem"),
                PRIVATE: path / (key_prefix + "-rsa-local-private.pem"),
            },
        },
        AES: {
            LOCAL_MODE: {PRIVATE: path / (key_prefix + "-aes-local.key")},
            RESTRICTED_MODE: {
                PRIVATE: path / (key_prefix + "-aes-restricted.key"),
            },
        },
        SALT: {
            LOCAL_MODE: {PRIVATE: path / (key_prefix + "-salt-local.key")},
            RESTRICTED_MODE: {
                PRIVATE: path / (key_prefix + "-salt-restricted.key"),
            },
        },
    }


def get_filenames(path: PurePath, key_prefix: str) -> list[PurePath]:
    filenames = []
    for _, v in get_template(path, key_prefix).items():
        for _, _v in v.items():
            for _, filename in _v.items():
                filenames.append(filename)
    return filenames


def write_msg(verbose, msg: str):
    if verbose:
        sys.stdout.write(msg)
