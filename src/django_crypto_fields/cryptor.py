from __future__ import annotations

from typing import TYPE_CHECKING

from Cryptodome import Random
from Cryptodome.Cipher import AES as AES_CIPHER

from .constants import AES, PRIVATE, PUBLIC, RSA
from .encoding import safe_encode
from .exceptions import EncryptionError
from .keys import encryption_keys
from .utils import append_padding, get_keypath_from_settings, remove_padding

if TYPE_CHECKING:
    from Cryptodome.Cipher._mode_cbc import CbcMode
    from Cryptodome.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher

__all__ = ["Cryptor"]


class Cryptor:
    """Base class for all classes providing RSA and AES encryption
    methods.

    The PEM file names and paths are in KEY_FILENAMES. KEYS is a copy
    of this except the filenames are replaced with the actual keys.
    """

    def __init__(self, algorithm, access_mode) -> None:
        self.algorithm = algorithm
        self.aes_encryption_mode: int = AES_CIPHER.MODE_CBC
        aes_key_attr: str = "_".join([AES, access_mode, PRIVATE, "key"])
        self.aes_key: bytes = getattr(encryption_keys, aes_key_attr)
        rsa_key_attr = "_".join([RSA, access_mode, PUBLIC, "key"])
        self.rsa_public_key: PKCS1OAEP_Cipher = getattr(encryption_keys, rsa_key_attr)
        rsa_key_attr = "_".join([RSA, access_mode, PRIVATE, "key"])
        self.rsa_private_key: PKCS1OAEP_Cipher = getattr(encryption_keys, rsa_key_attr)
        self.encrypt = getattr(self, f"_{self.algorithm.lower()}_encrypt")
        self.decrypt = getattr(self, f"_{self.algorithm.lower()}_decrypt")

    def _aes_encrypt(self, value: str | bytes) -> bytes:
        encoded_value = safe_encode(value)
        iv: bytes = Random.new().read(AES_CIPHER.block_size)
        cipher: CbcMode = AES_CIPHER.new(self.aes_key, self.aes_encryption_mode, iv)
        encoded_value = append_padding(encoded_value, cipher.block_size)
        secret = iv + cipher.encrypt(encoded_value)
        return secret

    def _aes_decrypt(self, secret: bytes) -> str:
        iv = secret[: AES_CIPHER.block_size]
        cipher: CbcMode = AES_CIPHER.new(self.aes_key, self.aes_encryption_mode, iv)
        encoded_value = cipher.decrypt(secret)[AES_CIPHER.block_size :]
        encoded_value = remove_padding(encoded_value)
        return encoded_value.decode() if encoded_value is not None else None

    def _rsa_encrypt(self, value: str | bytes) -> bytes:
        try:
            secret = self.rsa_public_key.encrypt(safe_encode(value))
        except (ValueError, TypeError) as e:
            raise EncryptionError(f"RSA encryption failed for value. Got '{e}'")
        return secret

    def _rsa_decrypt(self, secret: bytes) -> str:
        try:
            encoded_value = self.rsa_private_key.decrypt(secret)
        except ValueError as e:
            raise EncryptionError(
                f"{e} Using RSA from key_path=`{get_keypath_from_settings()}`."
            )
        return encoded_value.decode() if encoded_value is not None else None
