from __future__ import annotations

import binascii
from typing import TYPE_CHECKING

from Cryptodome import Random
from Cryptodome.Cipher import AES as AES_CIPHER

from .constants import AES, ENCODING, LOCAL_MODE, PRIVATE, PUBLIC, RSA
from .exceptions import EncryptionError
from .keys import encryption_keys
from .utils import get_keypath_from_settings

if TYPE_CHECKING:
    from Cryptodome.Cipher._mode_cbc import CbcMode
    from Cryptodome.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher


class Cryptor:
    """Base class for all classes providing RSA and AES encryption
    methods.

    The PEM file names and paths are in KEY_FILENAMES. KEYS is a copy
    of this except the filenames are replaced with the actual keys.
    """

    def __init__(self, algorithm: AES | RSA, access_mode: PRIVATE | LOCAL_MODE = None) -> None:
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

    def get_with_padding(self, plaintext: str | bytes, block_size: int) -> bytes:
        """Return string padded so length is a multiple of the block size.
        * store length of padding the last hex value.
        * if padding is 0, pad as if padding is 16.
        * AES_CIPHER.MODE_CFB should not be used, but was used
          without padding in the past. Continue to skip padding
          for this mode.
        """
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        if self.aes_encryption_mode == AES_CIPHER.MODE_CFB:
            padding_length = 0
        else:
            padding_length = (block_size - len(plaintext) % block_size) % block_size
            padding_length = padding_length or 16
        padded = (
            plaintext
            + (b"\x00" * (padding_length - 1))
            + binascii.a2b_hex(str(padding_length).zfill(2))
        )
        if len(padded) % block_size > 0:
            multiple = len(padded) / block_size
            raise EncryptionError(
                f"Padding error, got padded string not a multiple "
                f"of {block_size}. Got {multiple}"
            )
        return padded

    def get_without_padding(self, plaintext: str | bytes) -> bytes:
        """Return original plaintext without padding.

        Length of padding is stored in last two characters of
        plaintext.
        """
        if self.aes_encryption_mode == AES_CIPHER.MODE_CFB:
            return plaintext
        padding_length = int(binascii.b2a_hex(plaintext[-1:]))
        if not padding_length:
            return plaintext[:-1]
        return plaintext[:-padding_length]

    def _aes_encrypt(self, plaintext: str | bytes) -> bytes:
        iv: bytes = Random.new().read(AES_CIPHER.block_size)
        cipher: CbcMode = AES_CIPHER.new(self.aes_key, self.aes_encryption_mode, iv)
        padded_plaintext = self.get_with_padding(plaintext, cipher.block_size)
        return iv + cipher.encrypt(padded_plaintext)

    def _aes_decrypt(self, ciphertext: bytes) -> str:
        iv = ciphertext[: AES_CIPHER.block_size]
        cipher: CbcMode = AES_CIPHER.new(self.aes_key, self.aes_encryption_mode, iv)
        plaintext = cipher.decrypt(ciphertext)[AES_CIPHER.block_size :]
        return self.get_without_padding(plaintext).decode()

    def _rsa_encrypt(self, plaintext: str | bytes) -> bytes:
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        try:
            ciphertext = self.rsa_public_key.encrypt(plaintext)
        except (ValueError, TypeError) as e:
            raise EncryptionError(f"RSA encryption failed for value. Got '{e}'")
        return ciphertext

    def _rsa_decrypt(self, ciphertext: bytes) -> str:
        try:
            plaintext = self.rsa_private_key.decrypt(ciphertext)
        except ValueError as e:
            raise EncryptionError(
                f"{e} Using RSA from key_path=`{get_keypath_from_settings()}`."
            )
        return plaintext.decode(ENCODING)
