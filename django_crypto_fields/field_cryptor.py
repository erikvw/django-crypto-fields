from __future__ import annotations

import binascii
import hashlib
from typing import TYPE_CHECKING, Type

from Cryptodome.Cipher import AES as AES_CIPHER
from django.apps import apps as django_apps
from django.core.exceptions import ObjectDoesNotExist

from .constants import (
    AES,
    CIPHER_PREFIX,
    ENCODING,
    HASH_ALGORITHM,
    HASH_PREFIX,
    HASH_ROUNDS,
    PRIVATE,
    RSA,
    SALT,
)
from .cryptor import Cryptor
from .exceptions import (
    CipherError,
    EncryptionError,
    EncryptionKeyError,
    MalformedCiphertextError,
)
from .keys import encryption_keys
from .utils import get_crypt_model_cls, has_valid_value_or_raise, safe_encode_utf8

if TYPE_CHECKING:
    from .models import Crypt


class FieldCryptor:
    """Base class for django field classes with encryption.

    ciphertext = hash_prefix + hashed_value + cipher_prefix + secret

    The plaintext is hashed and stored by the user's model field.
    The plaintext is also encrypted and stored in the cipher model
    along with the hash. The user's model field object looks up
    the secret in the cipher model using the hash. The secret is
    decrypted and returned to the user's model field object.
    """

    crypt_model = "django_crypto_fields.crypt"

    def __init__(self, algorithm: str, access_mode: str):
        self._using = None
        self.algorithm = algorithm
        self.access_mode = access_mode
        self.aes_encryption_mode = AES_CIPHER.MODE_CBC
        self.cipher_buffer_key = f"{self.algorithm}_{self.access_mode}"
        self.cipher_buffer = {self.cipher_buffer_key: {}}
        self.keys = encryption_keys
        self.cryptor = Cryptor()
        self.hash_size: int = len(self.hash("Foo"))

    def __repr__(self) -> str:
        return f"FieldCryptor(algorithm='{self.algorithm}', mode='{self.access_mode}')"

    @property
    def salt_key(self):
        attr = "_".join([SALT, self.access_mode, PRIVATE])
        try:
            salt = getattr(self.keys, attr)
        except AttributeError as e:
            raise EncryptionKeyError(f"Invalid key. Got {attr}. {e}")
        return salt

    @property
    def crypt_model_cls(self) -> Type[Crypt]:
        """Returns the cipher model and avoids issues with model
        loading and field classes.
        """
        return get_crypt_model_cls()

    def hash(self, plaintext):
        """Returns a hexified hash of a plaintext value (as bytes).

        The hashed value is used as a signature of the "secret".
        """
        plaintext = safe_encode_utf8(plaintext)
        dk = hashlib.pbkdf2_hmac(HASH_ALGORITHM, plaintext, self.salt_key, HASH_ROUNDS)
        return binascii.hexlify(dk)

    def encrypt(self, value: str | bytes | None, update: bool | None = None):
        """Returns ciphertext as byte data using either an
        RSA or AES cipher.

        * 'value' is either plaintext or ciphertext
        * 'ciphertext' is a byte value of hash_prefix
          + hashed_value + cipher_prefix + secret.
          For example:
            enc1:::234234ed234a24enc2::\x0e\xb9\xae\x13s\x8d
              \xe7O\xbb\r\x99.
        * 'value' is not re-encrypted if already encrypted and properly
          formatted 'ciphertext'.
        """
        ciphertext = None
        update = True if update is None else update
        value = safe_encode_utf8(value)
        if value is not None and value != b"" and not self.is_encrypted(value):
            ciphertext = self.get_ciphertext(value)
            if update:
                self.update_crypt(ciphertext)
        return ciphertext

    def decrypt(self, hash_with_prefix: str):
        """Returns decrypted secret or None.

        Secret is retrieved from `Crypt` using the hash.

        hash_with_prefix = hash_prefix+hash.
        """
        plaintext = None
        hash_with_prefix = safe_encode_utf8(hash_with_prefix)
        if self.is_encrypted(hash_with_prefix):
            if secret := self.fetch_secret(hash_with_prefix):
                if self.algorithm == AES:
                    plaintext = self.cryptor.aes_decrypt(secret, self.access_mode)
                elif self.algorithm == RSA:
                    plaintext = self.cryptor.rsa_decrypt(secret, self.access_mode)
                else:
                    raise CipherError(
                        "Cannot determine algorithm for decryption."
                        " Valid options are {0}. Got {1}".format(
                            ", ".join(list(self.keys.key_filenames)), self.algorithm
                        )
                    )
        return plaintext

    @property
    def using(self):
        if not self._using:
            app_config = django_apps.get_app_config("django_crypto_fields")
            self._using = app_config.crypt_model_using
        return self._using

    def update_crypt(self, ciphertext):
        """Updates cipher model (Crypt) and temporary buffer."""
        if self.verify_ciphertext(ciphertext):
            hashed_value = self.get_hash(ciphertext)
            secret = self.get_secret(ciphertext)
            self.cipher_buffer[self.cipher_buffer_key].update({hashed_value: secret})
            try:
                crypt = self.crypt_model_cls.objects.using(self.using).get(
                    hash=hashed_value, algorithm=self.algorithm, mode=self.access_mode
                )
                crypt.secret = secret
                crypt.save()
            except ObjectDoesNotExist:
                self.crypt_model_cls.objects.using(self.using).create(
                    hash=hashed_value,
                    secret=secret,
                    algorithm=self.algorithm,
                    cipher_mode=self.aes_encryption_mode,
                    mode=self.access_mode,
                )

    def verify_ciphertext(self, ciphertext):
        """Returns ciphertext after verifying format prefix +
        hash + prefix + secret.
        """
        try:
            ciphertext.split(HASH_PREFIX.encode(ENCODING))[1]
        except IndexError:
            raise ValueError(f"Malformed ciphertext. Expected prefixes {HASH_PREFIX}")
        try:
            ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[1]
        except IndexError:
            raise ValueError(f"Malformed ciphertext. Expected prefixes {CIPHER_PREFIX}")
        try:
            if ciphertext[: len(HASH_PREFIX)] != HASH_PREFIX.encode(ENCODING):
                raise MalformedCiphertextError(
                    f"Malformed ciphertext. Expected hash prefix {HASH_PREFIX}"
                )
            if (
                len(
                    ciphertext.split(HASH_PREFIX.encode(ENCODING))[1].split(
                        CIPHER_PREFIX.encode(ENCODING)
                    )[0]
                )
                != self.hash_size
            ):
                raise MalformedCiphertextError(
                    f"Malformed ciphertext. Expected hash size of {self.hash_size}."
                )
        except IndexError:
            MalformedCiphertextError("Malformed ciphertext.")
        return ciphertext

    def get_prep_value(self, value: str | bytes | None) -> str | bytes | None:
        """Returns the prefix + hash as stored in the DB table column of
        your model's "encrypted" field.

        Used by get_prep_value()
        """
        if value is None or value in ["", b""]:
            pass  # return None or empty string/byte
        else:
            ciphertext = self.encrypt(value)
            value = ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[0]
            try:
                value.decode()
            except AttributeError:
                pass
        return value

    def get_ciphertext(self, value):
        cipher = None
        if self.algorithm == AES:
            cipher = self.cryptor.aes_encrypt
        elif self.algorithm == RSA:
            cipher = self.cryptor.rsa_encrypt
        try:
            ciphertext = (
                HASH_PREFIX.encode(ENCODING)
                + self.hash(value)
                + CIPHER_PREFIX.encode(ENCODING)
                + cipher(value, self.access_mode)
            )
        except AttributeError as e:
            raise CipherError(
                "Cannot determine cipher method. Unknown "
                "encryption algorithm. Valid options are {0}. "
                "Got {1} ({2})".format(", ".join(self.keys.key_filenames), self.algorithm, e)
            )
        return self.verify_ciphertext(ciphertext)

    def get_hash(self, ciphertext: bytes) -> bytes | None:
        """Returns the hashed_value given a ciphertext or None."""
        ciphertext = safe_encode_utf8(ciphertext)
        return ciphertext[len(HASH_PREFIX) :][: self.hash_size] or None

    def get_secret(self, ciphertext: bytes) -> bytes | None:
        """Returns the secret given a ciphertext."""
        if ciphertext is None:
            secret = None
        elif self.is_encrypted(ciphertext):
            secret = ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[1]
        else:
            raise CipherError("Expected a ciphertext or None")
        return secret

    def fetch_secret(self, hash_with_prefix: bytes):
        hashed_value = self.get_hash(hash_with_prefix)
        secret = self.cipher_buffer[self.cipher_buffer_key].get(hashed_value)
        if not secret:
            try:
                cipher = (
                    self.crypt_model_cls.objects.using(self.using)
                    .values("secret")
                    .get(hash=hashed_value, algorithm=self.algorithm, mode=self.access_mode)
                )
                secret = cipher.get("secret")
                self.cipher_buffer[self.cipher_buffer_key].update({hashed_value: secret})
            except ObjectDoesNotExist:
                raise EncryptionError(
                    f"Failed to get secret for given {self.algorithm} "
                    f"{self.access_mode} hash. Got '{hash_with_prefix}'"
                )
        return secret

    def is_encrypted(self, value: str | bytes | None) -> bool:
        """Returns True if value is encrypted.
        Value can be:
            * a string value
            * a well-formed hash
            * a well-formed hash+secret.
        """
        is_encrypted = False
        if value is not None:
            value = safe_encode_utf8(value)
            if value[: len(HASH_PREFIX)] == HASH_PREFIX.encode(ENCODING):
                has_secret = value[: len(CIPHER_PREFIX)] == CIPHER_PREFIX.encode(ENCODING)
                has_valid_value_or_raise(value, self.hash_size, has_secret=has_secret)
                is_encrypted = True
        return is_encrypted

    def mask(self, value, mask=None):
        """Returns 'mask' if value is encrypted."""
        mask = mask or "<encrypted>"
        if self.is_encrypted(value):
            return mask
        else:
            return value
