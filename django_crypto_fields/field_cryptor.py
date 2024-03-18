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
from .utils import get_crypt_model_cls

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

    def __init__(self, algorithm: str, mode: int):
        self._using = None
        self.algorithm = algorithm
        self.mode = mode
        self.aes_encryption_mode = AES_CIPHER.MODE_CBC
        self.cipher_buffer_key = f"{self.algorithm}_{self.mode}"
        self.cipher_buffer = {self.cipher_buffer_key: {}}
        self.keys = encryption_keys
        self.cryptor = Cryptor()
        self.hash_size: int = len(self.hash("Foo"))

    def __repr__(self) -> str:
        return f"FieldCryptor(algorithm='{self.algorithm}', mode='{self.mode}')"

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
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        attr = "_".join([SALT, self.mode, PRIVATE])
        try:
            salt = getattr(self.keys, attr)
        except AttributeError as e:
            raise EncryptionKeyError(f"Invalid key. Got {attr}. {e}")
        dk = hashlib.pbkdf2_hmac(HASH_ALGORITHM, plaintext, salt, HASH_ROUNDS)
        return binascii.hexlify(dk)

    def encrypt(self, value, update=None):
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
        try:
            ciphertext = value.encode(ENCODING)
        except AttributeError:
            ciphertext = value
        if ciphertext is None or value == b"":
            pass
        else:
            update = True if update is None else update
            if not self.is_encrypted(value):
                try:
                    if self.algorithm == AES:
                        cipher = self.cryptor.aes_encrypt
                    elif self.algorithm == RSA:
                        cipher = self.cryptor.rsa_encrypt
                    else:
                        cipher = None
                    ciphertext = (
                        HASH_PREFIX.encode(ENCODING)
                        + self.hash(value)
                        + CIPHER_PREFIX.encode(ENCODING)
                        + cipher(value, self.mode)
                    )
                    if update:
                        self.update_crypt(ciphertext)
                except AttributeError as e:
                    raise CipherError(
                        "Cannot determine cipher method. Unknown "
                        "encryption algorithm. Valid options are {0}. "
                        "Got {1} ({2})".format(
                            ", ".join(self.keys.key_filenames), self.algorithm, e
                        )
                    )
        return ciphertext

    def decrypt(self, hash_with_prefix: str):
        """Returns decrypted secret or None.

        Secret is retrieved from `Crypt` using the hash.

        hash_with_prefix = hash_prefix+hash.
        """
        plaintext = None
        try:
            hash_with_prefix = hash_with_prefix.encode(ENCODING)
        except AttributeError:
            pass
        if hash_with_prefix:
            if self.is_encrypted(hash_with_prefix):
                # hashed_value = self.get_hash(hash_with_prefix)
                secret = self.fetch_secret(hash_with_prefix)
                if secret:
                    if self.algorithm == AES:
                        plaintext = self.cryptor.aes_decrypt(secret, self.mode)
                    elif self.algorithm == RSA:
                        plaintext = self.cryptor.rsa_decrypt(secret, self.mode)
                    else:
                        raise CipherError(
                            "Cannot determine algorithm for decryption."
                            " Valid options are {0}. Got {1}".format(
                                ", ".join(list(self.keys.key_filenames)), self.algorithm
                            )
                        )
                else:
                    if hashed_value := self.get_hash(hash_with_prefix):
                        raise EncryptionError(
                            'Failed to decrypt. Could not find "secret" '
                            f" for hash '{hashed_value}'"
                        )
                    else:
                        raise EncryptionError("Failed to decrypt. Malformed ciphertext")
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
                    hash=hashed_value, algorithm=self.algorithm, mode=self.mode
                )
                crypt.secret = secret
                crypt.save()
            except ObjectDoesNotExist:
                self.crypt_model_cls.objects.using(self.using).create(
                    hash=hashed_value,
                    secret=secret,
                    algorithm=self.algorithm,
                    cipher_mode=self.aes_encryption_mode,
                    mode=self.mode,
                )

    def verify_ciphertext(self, ciphertext):
        """Returns ciphertext after verifying format prefix +
        hash + prefix + secret.
        """
        try:
            ciphertext.split(HASH_PREFIX.encode(ENCODING))[1]
        except IndexError:
            ValueError(f"Malformed ciphertext. Expected prefixes {HASH_PREFIX}")
        try:
            ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[1]
        except IndexError:
            ValueError(f"Malformed ciphertext. Expected prefixes {CIPHER_PREFIX}")
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

    def get_hash(self, ciphertext: bytes) -> bytes | None:
        """Returns the hashed_value given a ciphertext or None."""
        try:
            ciphertext.encode(ENCODING)
        except AttributeError:
            pass
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
                    .get(hash=hashed_value, algorithm=self.algorithm, mode=self.mode)
                )
                secret = cipher.get("secret")
                self.cipher_buffer[self.cipher_buffer_key].update({hashed_value: secret})
            except ObjectDoesNotExist:
                raise EncryptionError(
                    f"Failed to get secret for given {self.algorithm} "
                    f"{self.mode} hash. Got '{hash_with_prefix}'"
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
            try:
                value = value.encode(ENCODING)
            except AttributeError:
                pass
            if value[: len(HASH_PREFIX)] == HASH_PREFIX.encode(ENCODING):
                if not value[: len(CIPHER_PREFIX)] == CIPHER_PREFIX.encode(ENCODING):
                    self.verify_value(value, has_secret=False)
                    is_encrypted = True
                elif value[: len(CIPHER_PREFIX)] == CIPHER_PREFIX.encode(ENCODING):
                    self.verify_value(value, has_secret=True)
                    is_encrypted = True
        return is_encrypted

    def verify_value(self, value: str | bytes, has_secret=None) -> str | bytes:
        """Encodes the value, validates its format, and returns it
        or raises an exception.

        A value is either a value that can be encrypted or one that
        already is encrypted.

        * A value cannot just be equal to HASH_PREFIX or CIPHER_PREFIX;
        * A value prefixed with HASH_PREFIX must be followed by a
          valid hash (by length);
        * A value prefixed with HASH_PREFIX + hashed_value +
          CIPHER_PREFIX must be followed by some text;
        * A value prefix by CIPHER_PREFIX must be followed by
          some text;
        """
        has_secret = True if has_secret is None else has_secret
        try:
            bytes_value = value.encode(ENCODING)
        except AttributeError:
            bytes_value = value
        if bytes_value is not None and bytes_value != b"":
            if bytes_value in [
                HASH_PREFIX.encode(ENCODING),
                CIPHER_PREFIX.encode(ENCODING),
            ]:
                raise MalformedCiphertextError(
                    "Expected a value, got just the encryption prefix."
                )
            self.verify_hash(bytes_value)
            if has_secret:
                self.verify_secret(bytes_value)
        return value  # note, is original passed value

    def verify_hash(self, ciphertext: bytes) -> bool:
        """Verifies hash segment of ciphertext (bytes) and
        raises an exception if not OK.
        """
        try:
            ciphertext = ciphertext.encode(ENCODING)
        except AttributeError:
            pass
        hash_prefix = HASH_PREFIX.encode(ENCODING)
        if ciphertext == HASH_PREFIX.encode(ENCODING):
            raise MalformedCiphertextError(f"Ciphertext has not hash. Got {ciphertext}")
        if not ciphertext[: len(hash_prefix)] == hash_prefix:
            raise MalformedCiphertextError(
                f"Ciphertext must start with {hash_prefix}. "
                f"Got {ciphertext[:len(hash_prefix)]}"
            )
        hash_value = ciphertext[len(hash_prefix) :].split(CIPHER_PREFIX.encode(ENCODING))[0]
        if len(hash_value) != self.hash_size:
            raise MalformedCiphertextError(
                "Expected hash prefix to be followed by a hash. "
                "Got something else or nothing"
            )
        return True

    @staticmethod
    def verify_secret(ciphertext: bytes) -> bool:
        """Verifies secret segment of ciphertext and raises an
        exception if not OK.
        """
        if ciphertext[: len(HASH_PREFIX)] == HASH_PREFIX.encode(ENCODING):
            try:
                secret = ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[1]
                if len(secret) == 0:
                    raise MalformedCiphertextError(
                        "Expected cipher prefix to be followed by a secret. " "Got nothing (1)"
                    )
            except IndexError:
                raise MalformedCiphertextError(
                    "Expected cipher prefix to be followed by a secret. " "Got nothing (2)"
                )
        if (
            ciphertext[-1 * len(CIPHER_PREFIX) :] == CIPHER_PREFIX.encode(ENCODING)
            and len(ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[1]) == 0
        ):
            raise MalformedCiphertextError(
                "Expected cipher prefix to be followed by a secret. " "Got nothing (3)"
            )
        return True

    def mask(self, value, mask=None):
        """Returns 'mask' if value is encrypted."""
        mask = mask or "<encrypted>"
        if self.is_encrypted(value):
            return mask
        else:
            return value
