from __future__ import annotations

from typing import TYPE_CHECKING, Type

from Cryptodome.Cipher import AES as AES_CIPHER
from django.apps import apps as django_apps
from django.core.exceptions import ObjectDoesNotExist

from .cipher import Cipher, CipherParser
from .constants import AES, CIPHER_PREFIX, ENCODING, HASH_PREFIX, PRIVATE, RSA, SALT
from .cryptor import Cryptor
from .exceptions import EncryptionError, EncryptionKeyError, InvalidEncryptionAlgorithm
from .keys import encryption_keys
from .utils import get_crypt_model_cls, make_hash, safe_decode, safe_encode_utf8

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
    cryptor_cls = Cryptor
    cipher_cls = Cipher

    def __init__(self, algorithm: str, access_mode: str):
        self._using = None
        self._algorithm = None
        self.algorithm = algorithm
        self.access_mode = access_mode
        self.aes_encryption_mode = AES_CIPHER.MODE_CBC
        self.cipher_buffer_key = f"{self.algorithm}_{self.access_mode}"
        self.cipher_buffer = {self.cipher_buffer_key: {}}
        self.keys = encryption_keys
        self.cryptor = self.cryptor_cls(algorithm=algorithm, access_mode=access_mode)
        self.hash_size: int = len(self.hash("Foo"))

    def __repr__(self) -> str:
        return f"FieldCryptor(algorithm='{self.algorithm}', mode='{self.access_mode}')"

    @property
    def algorithm(self):
        return self._algorithm

    @algorithm.setter
    def algorithm(self, value):
        self._algorithm = value
        if value not in [AES, RSA]:
            raise InvalidEncryptionAlgorithm(
                f"Invalid encryption algorithm. Expected 'aes' or 'rsa'. Got {value}"
            )

    def hash(self, value):
        return make_hash(value, self.salt_key)

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

    def encrypt(self, value: str | bytes | None, update: bool | None = None):
        """Returns either an RSA or AES cipher.

        * 'value' is either plaintext or ciphertext
        * 'cipher' is a byte value of hash_prefix
          + hashed_value + cipher_prefix + secret.
          For example:
            enc1:::234234ed234a24enc2::\x0e\xb9\xae\x13s\x8d
              \xe7O\xbb\r\x99.
        * 'value' is not re-encrypted if already encrypted and properly
          formatted 'ciphertext'.
        """
        cipher = None
        update = True if update is None else update
        encoded_value = safe_encode_utf8(value)
        if encoded_value and not self.is_encrypted(encoded_value):
            cipher = self.cipher_cls(value, self.salt_key, encrypt=self.cryptor.encrypt)
            if update:
                self.update_crypt(cipher)
        return getattr(cipher, "cipher", encoded_value)

    def decrypt(self, hash_with_prefix: str | bytes):
        """Returns decrypted secret or None.

        Secret is retrieved from `Crypt` using the hash_with_prefix
        coming from the field of the user model.

        hash_with_prefix = hash_prefix+hash_value.
        """
        hash_with_prefix = safe_encode_utf8(hash_with_prefix)
        if hash_with_prefix and self.is_encrypted(hash_with_prefix):
            if secret := self.fetch_secret(hash_with_prefix):
                return self.cryptor.decrypt(secret)
        return None

    @property
    def using(self):
        if not self._using:
            app_config = django_apps.get_app_config("django_crypto_fields")
            self._using = app_config.crypt_model_using
        return self._using

    def update_crypt(self, cipher: Cipher):
        """Updates Crypt model and cipher_buffer."""
        self.cipher_buffer[self.cipher_buffer_key].update({cipher.hashed_value: cipher.secret})
        try:
            crypt = self.crypt_model_cls.objects.using(self.using).get(
                hash=cipher.hashed_value, algorithm=self.algorithm, mode=self.access_mode
            )
            crypt.secret = cipher.secret
            crypt.save()
        except ObjectDoesNotExist:
            self.crypt_model_cls.objects.using(self.using).create(
                hash=cipher.hashed_value,
                secret=cipher.secret,
                algorithm=self.algorithm,
                cipher_mode=self.aes_encryption_mode,
                mode=self.access_mode,
            )

    def get_prep_value(self, value: str | bytes | None) -> str | bytes | None:
        """Returns the prefix + hash_value as stored in the DB table column of
        your model's "encrypted" field.

        Used by get_prep_value()
        """
        hash_with_prefix = None
        if value is None or value in ["", b""]:
            pass  # return None or empty string/byte
        else:
            cipher = self.encrypt(value)
            hash_with_prefix = cipher.split(CIPHER_PREFIX.encode(ENCODING))[0]
            hash_with_prefix = safe_decode(hash_with_prefix)
        return hash_with_prefix or value

    def fetch_secret(self, hash_with_prefix: bytes):
        """Fetch the secret from the DB or the buffer using
        the hashed_value as the lookup.

        If not found in buffer, lookup in DB and update the buffer.

        A secret is the segment to follow the `enc2:::`.
        """
        hash_with_prefix = safe_encode_utf8(hash_with_prefix)
        hashed_value = hash_with_prefix[len(HASH_PREFIX) :][: self.hash_size] or None
        secret = self.cipher_buffer[self.cipher_buffer_key].get(hashed_value)
        if not secret:
            try:
                data = (
                    self.crypt_model_cls.objects.using(self.using)
                    .values("secret")
                    .get(hash=hashed_value, algorithm=self.algorithm, mode=self.access_mode)
                )
                secret = data.get("secret")
                self.cipher_buffer[self.cipher_buffer_key].update({hashed_value: secret})
            except ObjectDoesNotExist:
                raise EncryptionError(
                    f"EncryptionError. Failed to get secret for given {self.algorithm} "
                    f"{self.access_mode} hash. Got '{str(hash_with_prefix)}'"
                )
        return secret

    def is_encrypted(self, value: str | bytes | None) -> bool:
        """Returns True if value is encrypted.

        An encrypted value starts with the hash_prefix.

        Inspects a value that is:
            * a string value -> False
            * a well-formed hash
            * a well-formed hash_prefix + hash -> True
            * a well-formed hash + secret.
        """
        is_encrypted = False
        if value is not None:
            value = safe_encode_utf8(value)
            if value.startswith(safe_encode_utf8(HASH_PREFIX)):
                p = CipherParser(value, self.salt_key)
                p.validate_hashed_value()
                is_encrypted = True
        return is_encrypted

    def mask(self, value, mask=None):
        """Returns 'mask' if value is encrypted."""
        mask = mask or "<encrypted>"
        if self.is_encrypted(value):
            return mask
        else:
            return value
