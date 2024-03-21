from __future__ import annotations

import sys
from pathlib import Path, PurePath
from typing import Iterator

from ..constants import AES, LOCAL_MODE, PRIVATE, PUBLIC, RESTRICTED_MODE, RSA, SALT

__all__ = [
    "get_template",
    "get_filenames",
    "key_files_exist",
    "write_msg",
    "get_values_from_nested_dict",
]


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
    for value in get_values_from_nested_dict(get_template(path, key_prefix)):
        filenames.append(value)
    return filenames


def key_files_exist(path: PurePath, key_prefix: str) -> bool:
    """Return True if all key files exist in the key path."""
    not_exists = []
    for filename in get_filenames(path, key_prefix):
        if not Path(filename).exists():
            not_exists.append(filename)
    return len(not_exists) == 0


def write_msg(verbose, msg: str) -> None:
    if verbose:
        sys.stdout.write(msg)


def get_values_from_nested_dict(nested_dict: dict) -> Iterator:
    """Recursively traverse nested dictionary to yield values."""
    for key, value in nested_dict.items():
        if isinstance(value, dict):
            yield from get_values_from_nested_dict(value)
        else:
            yield value
