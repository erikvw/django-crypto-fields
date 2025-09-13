from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path, PurePath

from ..constants import AES, LOCAL_MODE, PRIVATE, PUBLIC, RESTRICTED_MODE, RSA, SALT

__all__ = [
    "get_filenames",
    "get_template",
    "get_values_from_nested_dict",
    "key_files_exist",
    "write_msg",
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
    return [v for v in get_values_from_nested_dict(get_template(path, key_prefix))]


def key_files_exist(path: PurePath, key_prefix: str) -> bool:
    """Return True if all key files exist in the key path."""
    return len([f for f in get_filenames(path, key_prefix) if not Path(f).exists()]) == 0


def write_msg(verbose, msg: str) -> None:
    if verbose:
        sys.stdout.write(msg)


def get_values_from_nested_dict(nested_dict: dict) -> Iterator:
    """Recursively traverse nested dictionary to yield values."""
    for value in nested_dict.values():
        if isinstance(value, dict):
            yield from get_values_from_nested_dict(value)
        else:
            yield value
