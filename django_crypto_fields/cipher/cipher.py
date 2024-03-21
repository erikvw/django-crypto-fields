from __future__ import annotations

from typing import Callable

from ..constants import CIPHER_PREFIX, HASH_PREFIX
from ..utils import make_hash, safe_encode_utf8

__all__ = ["Cipher"]


class Cipher:
    """A class that given a value builds a cipher of the format
        hash_prefix + hashed_value + cipher_prefix + secret.
    .
      For example:
        enc1:::234234ed234a24enc2::\x0e\xb9\xae\x13s\x8d
              \xe7O\xbb\r\x99.

        The secret is encrypted using the passed `encrypt` callable.
    """

    def __init__(
        self,
        value: str | bytes,
        salt_key: bytes,
        encrypt: Callable[[bytes], bytes] | None = None,
    ):
        encoded_value = safe_encode_utf8(value)
        self.hash_prefix = b""
        self.hashed_value = b""
        self.cipher_prefix = b""
        self.secret = b""
        if salt_key:
            self.hash_prefix: bytes = safe_encode_utf8(HASH_PREFIX)
            self.hashed_value: bytes = make_hash(encoded_value, salt_key)
        if encrypt:
            self.secret = encrypt(encoded_value)
            self.cipher_prefix: bytes = safe_encode_utf8(CIPHER_PREFIX)

    @property
    def cipher(self) -> bytes:
        return self.hash_with_prefix + self.secret_with_prefix

    @property
    def hash_with_prefix(self) -> bytes:
        return self.hash_prefix + self.hashed_value

    @property
    def secret_with_prefix(self) -> bytes:
        return self.cipher_prefix + self.secret
