from __future__ import annotations

from Cryptodome.Cipher import AES as AES_CIPHER
from django.apps import apps as django_apps
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist

from .cipher import Cipher
from .constants import (
    AES,
    CIPHER_PREFIX,
    HASH_PREFIX,
    LOCAL_MODE,
    PRIVATE,
    RESTRICTED_MODE,
    RSA,
    SALT,
)
from .cryptor import Cryptor
from .exceptions import (
    DjangoCryptoFieldsError,
    EncryptionError,
    EncryptionKeyError,
    InvalidEncryptionAlgorithm,
)
from .keys import encryption_keys
from .utils import get_crypt_model_cls, make_hash

__all__ = ["FieldCryptor"]


class FieldCryptor:
    """Base class for django field classes with encryption.

    ciphertext = hash_prefix + hashed_value + cipher_prefix + secret

    The plaintext is hashed and stored by the user's model field.
    The plaintext is also encrypted and stored in the cipher model
    along with the hash. The user's model field object looks up
    the secret in the cipher model using the hash. The secret is
    decrypted and returned to the user's model field object.
    """

    cryptor_cls = Cryptor
    cipher_cls = Cipher

    def __init__(
        self,
        algorithm: str,
        access_mode: str,
    ):
        self._using = None
        self._algorithm = None
        self._access_mode = None
        self._cryptor = None
        self.algorithm = algorithm
        self.access_mode = access_mode
        self.cipher_buffer_key = b"{self.algorithm}_{self.access_mode}"
        self.cipher_buffer = {self.cipher_buffer_key: {}}
        self.keys = encryption_keys
        self.hash_size: int = len(self.hash("Foo"))

    def __repr__(self) -> str:
        return f"FieldCryptor(algorithm='{self.algorithm}', mode='{self.access_mode}')"

    @property
    def cryptor(self) -> Cryptor:
        if not self._cryptor:
            self._cryptor = self.cryptor_cls(
                algorithm=self.algorithm, access_mode=self.access_mode
            )
        return self._cryptor

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @algorithm.setter
    def algorithm(self, value: str):
        self._algorithm = value
        if value not in [AES, RSA]:
            raise InvalidEncryptionAlgorithm(
                f"Invalid encryption algorithm. Expected 'aes' or 'rsa'. Got {value}"
            )

    @property
    def access_mode(self) -> str:
        return self._access_mode

    @access_mode.setter
    def access_mode(self, value: str):
        self._access_mode = value
        if value not in [LOCAL_MODE, PRIVATE, RESTRICTED_MODE]:
            raise InvalidEncryptionAlgorithm(
                "Invalid encryption access mode. Expected "
                f"'{LOCAL_MODE}' or '{PRIVATE}' or {RESTRICTED_MODE}. Got {value}."
            )

    def hash(self, value: str) -> bytes:
        return make_hash(value, self.salt_key)

    @property
    def salt_key(self) -> bytes:
        attr: str = "_".join([SALT, self.access_mode, PRIVATE])
        try:
            salt: bytes = getattr(self.keys, attr)
        except AttributeError as e:
            raise EncryptionKeyError(f"Invalid key. Got {attr}. {e}")
        return salt

    def encrypt(self, value: str | None, update: bool | None = None) -> bytes:
        """Returns either an RSA or AES cipher of the format
        hash_prefix + hashed_value + cipher_prefix + secret.
        * 'update' if True updates the value in the Crypt model
        * `cipher.cipher` instance formats the cipher. For example:
          enc1:::234234ed234a24enc2::\x0e\xb9\xae\x13s\x8d\xe7O\xbb\r\x99.
        * 'value' is not re-encrypted if already encrypted and properly
          formatted `cipher.cipher` byte value.
        """
        cipher = None
        update = True if update is None else update
        if value is not None and not self.is_encrypted(value):
            cipher = self.cipher_cls(value, self.salt_key, encrypt=self.cryptor.encrypt)
            if update:
                self.update_crypt(cipher)
        return getattr(cipher, "cipher", value)

    def decrypt(self, hash_with_prefix: bytes) -> str | None:
        """Returns decrypted secret or None.

        Will raise a TypeError if `hash_with_prefix` is empty.

        Secret is retrieved from `Crypt` using the hash_with_prefix
        coming from the field of the user model.

        hash_with_prefix:bytes = hash_prefix + hash_value.

        See also BaseField.from_db_value.
        """
        if secret := self.fetch_secret(hash_with_prefix):
            return self.cryptor.decrypt(secret)
        return None

    @property
    def using(self):
        if not self._using:
            app_config = django_apps.get_app_config("django_crypto_fields")
            self._using = app_config.crypt_model_using
        return self._using

    @property
    def cache_key_prefix(self) -> bytes:
        algorithm = self.algorithm.encode()
        access_mode = self.access_mode.encode()
        prefix = getattr(settings, "CACHE_CRYPTO_KEY_PREFIX", "crypto").encode()
        return prefix + algorithm + b"-" + access_mode + b"-"

    def update_crypt(self, cipher: Cipher) -> None:
        """Updates Crypt model and the cache.

        `hash_value` is stored as a string to make use of the
        unique constraint on field `hash`.
        """
        opts = dict(
            hash=cipher.hashed_value.decode(),
            algorithm=self.algorithm,
            mode=self.access_mode,
            cipher_mode=AES_CIPHER.MODE_CBC,
        )
        if not get_crypt_model_cls().objects.using(self.using).filter(**opts).exists():
            get_crypt_model_cls().objects.using(self.using).create(
                secret=cipher.secret, **opts
            )
        cache.set(self.cache_key_prefix + cipher.hashed_value, cipher.secret)

    def get_prep_value(self, value: str | None) -> str | None:
        """Returns the prefix + hash_value, an empty string, or None
        prepared for saving into the column of your model's "encrypted"
        field.

        Used by field_cls.get_prep_value()
        """
        if value is not None:
            cipher = self.encrypt(value)
            return cipher.split(CIPHER_PREFIX.encode())[0].decode()
        return value

    def fetch_secret(self, hash_with_prefix: bytes) -> bytes | None:
        """Fetch the secret from the DB or the buffer using
        the hashed_value as the lookup.

        If not found in cache, lookup in DB and update the cache.

        A secret is the segment to follow the `enc2:::`.
        """
        secret = None
        # hash_with_prefix = self.safe_encode(hash_with_prefix.encode()
        if type(hash_with_prefix) is not bytes:
            raise DjangoCryptoFieldsError("hash_with_prefix must be bytes")
        if hashed_value := hash_with_prefix[len(HASH_PREFIX) :][: self.hash_size] or None:
            secret = cache.get(self.cache_key_prefix + hashed_value, None)
            if not secret:
                try:
                    data = (
                        get_crypt_model_cls()
                        .objects.using(self.using)
                        .values("secret")
                        .get(
                            hash=hashed_value.decode(),
                            algorithm=self.algorithm,
                            mode=self.access_mode,
                        )
                    )
                except ObjectDoesNotExist:
                    raise EncryptionError(
                        f"EncryptionError. Failed to get secret for given {self.algorithm} "
                        f"{self.access_mode} hash. Got '{str(hash_with_prefix)}'"
                    )
                else:
                    secret = data.get("secret")
                    cache.set(self.cache_key_prefix + hashed_value, secret)
        return secret

    @staticmethod
    def is_encrypted(value: str | bytes | None) -> bool:
        """Returns True if value is encrypted.

        An encrypted value starts with the hash_prefix.
        """
        if type(value) is not bytes:
            value = value.encode() if value is not None else value
        if value and value.startswith(HASH_PREFIX.encode()):
            return True
        return False

    def mask(self, value, mask=None):
        """Returns 'mask' if value is encrypted."""
        mask = mask or "<encrypted>"
        return mask if self.is_encrypted(value) else value
