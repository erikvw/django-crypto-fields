import binascii

from Crypto import Random
from Crypto.Cipher import AES as AES_CIPHER
from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import AppRegistryNotReady

from .constants import AES, ENCODING, PRIVATE, PUBLIC, RSA
from .exceptions import EncryptionError


class Cryptor(object):
    """Base class for all classes providing RSA and AES encryption
    methods.

    The PEM file names and paths are in KEY_FILENAMES. KEYS is a copy
    of this except the filenames are replaced with the actual keys.
    """

    def __init__(self, keys=None, aes_encryption_mode=None):
        self.aes_encryption_mode = aes_encryption_mode
        if not self.aes_encryption_mode:
            try:
                # do not use MODE_CFB, see comments in pycrypto.blockalgo.py
                self.aes_encryption_mode = settings.AES_ENCRYPTION_MODE
            except AttributeError:
                self.aes_encryption_mode = AES_CIPHER.MODE_CBC
        try:
            # ignore "keys" parameter if Django is loaded
            self.keys = django_apps.get_app_config(
                "django_crypto_fields"
            ).encryption_keys
        except AppRegistryNotReady:
            self.keys = keys

    def padded(self, plaintext, block_size):
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

    def unpadded(self, plaintext, block_size):
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

    def aes_encrypt(self, plaintext, mode):
        aes_key = "_".join([AES, mode, PRIVATE, "key"])
        iv = Random.new().read(AES_CIPHER.block_size)
        cipher = AES_CIPHER.new(
            getattr(self.keys, aes_key), self.aes_encryption_mode, iv
        )
        padded_plaintext = self.padded(plaintext, cipher.block_size)
        return iv + cipher.encrypt(padded_plaintext)

    def aes_decrypt(self, ciphertext, mode):
        aes_key = "_".join([AES, mode, PRIVATE, "key"])
        iv = ciphertext[: AES_CIPHER.block_size]
        cipher = AES_CIPHER.new(
            getattr(self.keys, aes_key), self.aes_encryption_mode, iv
        )
        plaintext = cipher.decrypt(ciphertext)[AES_CIPHER.block_size :]
        return self.unpadded(plaintext, cipher.block_size).decode()

    def rsa_encrypt(self, plaintext, mode):
        rsa_key = "_".join([RSA, mode, PUBLIC, "key"])
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        try:
            ciphertext = getattr(self.keys, rsa_key).encrypt(plaintext)
        except (ValueError, TypeError) as e:
            raise EncryptionError(f"RSA encryption failed for value. Got '{e}'")
        return ciphertext

    def rsa_decrypt(self, ciphertext, mode):
        rsa_key = "_".join([RSA, mode, PRIVATE, "key"])
        try:
            plaintext = getattr(self.keys, rsa_key).decrypt(ciphertext)
        except ValueError as e:
            raise EncryptionError(
                f"{e} Using {rsa_key} from key_path=`{settings.KEY_PATH}`."
            )
        return plaintext.decode(ENCODING)
