from __future__ import annotations

from ..constants import CIPHER_PREFIX, HASH_PREFIX
from ..exceptions import MalformedCiphertextError
from ..utils import make_hash

__all__ = ["CipherParser"]


class CipherParser:
    def __init__(self, cipher: bytes, salt_key: bytes | None = None):
        self._cipher_prefix = None
        self._hash_prefix = None
        self._hashed_value = None
        self._secret = None
        self.cipher = cipher
        self.salt_key = salt_key
        self.validate_hashed_value()
        self.validate_secret()

    @property
    def hash_prefix(self) -> bytes | None:
        if self.cipher:
            hash_prefix = HASH_PREFIX.encode()
            self._hash_prefix = hash_prefix if self.cipher.startswith(hash_prefix) else None
        return self._hash_prefix

    @property
    def cipher_prefix(self) -> bytes | None:
        if self.cipher:
            cipher_prefix = CIPHER_PREFIX.encode()
            self._cipher_prefix = cipher_prefix if cipher_prefix in self.cipher else None
        return self._cipher_prefix

    @property
    def hashed_value(self) -> bytes | None:
        if self.cipher and self.cipher.startswith(self.hash_prefix):
            self._hashed_value = self.cipher.split(self.hash_prefix)[1].split(
                self.cipher_prefix
            )[0]
        return self._hashed_value

    @property
    def secret(self) -> bytes | None:
        if self.cipher and CIPHER_PREFIX.encode() in self.cipher:
            self._secret = self.cipher.split(self.cipher_prefix)[1]
        return self._secret

    def validate_hashed_value(self) -> None:
        if self.hash_prefix and not self.hashed_value:
            raise MalformedCiphertextError("Invalid hashed_value. Got None.")
        elif self.salt_key and len(self.hashed_value) != len(make_hash("Foo", self.salt_key)):
            raise MalformedCiphertextError("Invalid hashed_value. Incorrect size.")

    def validate_secret(self) -> None:
        if self.cipher_prefix and not self.secret:
            raise MalformedCiphertextError("Invalid secret. Got None.")
