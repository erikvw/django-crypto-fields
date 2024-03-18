from __future__ import annotations

import binascii
from typing import TYPE_CHECKING

from Cryptodome import Random
from Cryptodome.Cipher import AES as AES_CIPHER

from .constants import AES, ENCODING, PRIVATE, PUBLIC, RSA
from .exceptions import EncryptionError
from .keys import encryption_keys
from .utils import get_keypath_from_settings

if TYPE_CHECKING:
    from Cryptodome.Cipher._mode_cbc import CbcMode
    from Cryptodome.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher

    from .keys import Keys


class Cryptor:
    """Base class for all classes providing RSA and AES encryption
    methods.

    The PEM file names and paths are in KEY_FILENAMES. KEYS is a copy
    of this except the filenames are replaced with the actual keys.
    """

    def __init__(self):
        self.aes_encryption_mode: int = AES_CIPHER.MODE_CBC
        self.keys: Keys = encryption_keys

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

    def aes_encrypt(self, plaintext: str | bytes, mode: str) -> bytes:
        aes_key_attr: str = "_".join([AES, mode, PRIVATE, "key"])
        aes_key: bytes = getattr(self.keys, aes_key_attr)
        iv: bytes = Random.new().read(AES_CIPHER.block_size)
        cipher: CbcMode = AES_CIPHER.new(aes_key, self.aes_encryption_mode, iv)
        padded_plaintext = self.get_with_padding(plaintext, cipher.block_size)
        return iv + cipher.encrypt(padded_plaintext)

    def aes_decrypt(self, ciphertext: bytes, mode: str) -> str:
        aes_key_attr: str = "_".join([AES, mode, PRIVATE, "key"])
        aes_key: bytes = getattr(self.keys, aes_key_attr)
        iv = ciphertext[: AES_CIPHER.block_size]
        cipher: CbcMode = AES_CIPHER.new(aes_key, self.aes_encryption_mode, iv)
        plaintext = cipher.decrypt(ciphertext)[AES_CIPHER.block_size :]
        return self.get_without_padding(plaintext).decode()

    def rsa_encrypt(self, plaintext: str | bytes, mode: int) -> bytes:
        rsa_key_attr = "_".join([RSA, mode, PUBLIC, "key"])
        rsa_key: PKCS1OAEP_Cipher = getattr(self.keys, rsa_key_attr)
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        try:
            ciphertext = rsa_key.encrypt(plaintext)
        except (ValueError, TypeError) as e:
            raise EncryptionError(f"RSA encryption failed for value. Got '{e}'")
        return ciphertext

    def rsa_decrypt(self, ciphertext: bytes, mode: str) -> str:
        rsa_key_attr = "_".join([RSA, mode, PRIVATE, "key"])
        rsa_key: PKCS1OAEP_Cipher = getattr(self.keys, rsa_key_attr)
        try:
            plaintext = rsa_key.decrypt(ciphertext)
        except ValueError as e:
            raise EncryptionError(
                f"{e} Using {rsa_key_attr} from key_path=`{get_keypath_from_settings()}`."
            )
        return plaintext.decode(ENCODING)
