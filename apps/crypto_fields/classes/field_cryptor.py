import binascii
import hashlib
import logging

try:
    from django.apps import apps
except ImportError:
    from django.db import models  # < Django 1.7

from .cryptor import Cryptor
from .cipher_buffer import cipher_buffer
from .constants import (KEY_FILENAMES, HASH_PREFIX, CIPHER_PREFIX, ENCODING,
                        HASH_ALGORITHM, HASH_ROUNDS)

from ..exceptions import CipherError, EncryptionError, MalformedCiphertextError

logger = logging.getLogger(__name__)


class FieldCryptor(object):
    """ Base class for django field classes with encryption.

    ciphertext = hash_prefix + hashed_value + cipher_prefix + secret

    The plaintext is hashed and stored by the user's model field. The plaintext is
    also encrypted and stored in the cipher model along with the hash. The user's
    model field object looks up the secret in the cipher model using the hash.
    The secret is decrypted and returned to the user's model field object.

    """
    def __init__(self, algorithm, mode):
        self._cipher_model = None
        self.algorithm = algorithm
        self.mode = mode
        self.cryptor = Cryptor()
        self.hash_size = len(self.hash('Foo', 'local'))

    def get_model(self):
        """Returns the get_model function."""
        try:
            return apps.get_model  # >= Django 1.7
        except NameError:
            return models.loading.get_model  # < Django 1.7

    @property
    def cipher_model(self):
        """Returns the cipher model and avoids issues with model loading and field classes."""
        if not self._cipher_model:
            self._cipher_model = self.get_model('crypto_fields', 'crypt')
        return self._cipher_model

    def hash(self, plaintext, mode):
        """Returns a hexified hash of a plaintext value.

        The hashed value is used as a reference to the "secret"."""
        salt = self.KEYS.get('salt').get(mode).get('private')
        dk = hashlib.pbkdf2_hmac(HASH_ALGORITHM, plaintext.encode('utf-8'), salt, HASH_ROUNDS)
        return binascii.hexlify(dk)

    def encrypt(self, value):
        """ Returns ciphertext as byte data using either an RSA or AES cipher.

        * 'value' is either plaintext or ciphertext
        * 'ciphertext' is a byte value of hash_prefix + hashed_value + cipher_prefix + secret.
          For example: enc1:::234234ed234a24enc2::\x0e\xb9\xae\x13s\x8d\xe7O\xbb\r\x99.
        * 'value' is not re-encrypted if already encrypted and properly formatted 'ciphertext'.
        """
        if self.is_encrypted(value):
            try:
                ciphertext = value.encode(ENCODING)
            except AttributeError:
                ciphertext = value
        else:
            try:
                if self.algorithm == 'aes':
                    cipher = self.cryptor.aes_encrypt
                elif self.algorithm == 'rsa':
                    cipher = self.cryptor.rsa_encrypt
                else:
                    cipher = None
                ciphertext = (HASH_PREFIX.encode(ENCODING) + self.hash(value, self.mode) +
                              CIPHER_PREFIX.encode(ENCODING) + cipher(value, self.mode))
            except AttributeError:
                raise CipherError(
                    'Cannot determine cipher method. Unknown encryption algorithm. '
                    'Valid options are {0}. Got {1}'.format(', '.join(KEY_FILENAMES), self.algorithm))
        return ciphertext

    def decrypt(self, ciphertext):
        """ Decrypts "secret" segment of 'ciphertext'.

        ciphertext = fully formed ciphertext OR hash_prefix+hash OR cipher_prefix+secret."""
        plaintext = None
        if ciphertext:
            if self.is_encrypted(ciphertext):
                if ciphertext[:len(HASH_PREFIX)] == HASH_PREFIX.encode(ENCODING):
                    hashed_value = self.get_hash(ciphertext)
                    secret = self.get_secret(ciphertext, hashed_value)
                else:
                    secret = ciphertext[len(CIPHER_PREFIX):]  # secret is not a hash
                if secret:
                    if self.algorithm == 'aes':
                        plaintext = self.cryptor.aes_decrypt(secret, self.mode)
                    elif self.algorithm == 'rsa':
                        plaintext = self.cryptor.rsa_decrypt(secret, self.mode)
                    else:
                        raise CipherError(
                            'Cannot determine algorithm for decryption.'
                            ' Valid options are {0}. Got {1}'.format(
                                ', '.join(list(KEY_FILENAMES)), self.algorithm))
                else:
                    hashed_value = self.get_hash(ciphertext)
                    if hashed_value:
                        raise EncryptionError(
                            'Failed to decrypt. Could not find "secret" '
                            ' for hash \'{0}\''.format(hashed_value))
                    else:
                        raise EncryptionError('Failed to decrypt. Malformed ciphertext')
        return plaintext or ciphertext

    def update_cipher_model(self, ciphertext):
        """ Updates cipher model (Crypt) and temporary buffer."""
        if ciphertext:
            ciphertext = self.verify_ciphertext(ciphertext)
            hashed_value = self.get_hash(ciphertext)
            secret = self.get_secret(ciphertext, hashed_value)
            found = cipher_buffer.retrieve_secret(hashed_value)
            if not found:
                found = self.cipher_model.objects.filter(hash=hashed_value).exists()
            if found and secret:
                self.cipher_model.objects.filter(hash=hashed_value).update(secret=secret)
            elif secret:
                self.cipher_model.objects.create(
                    hash=hashed_value,
                    secret=secret,
                    algorithm=self.algorithm,
                    mode=self.mode)
            else:
                pass

    def verify_ciphertext(self, ciphertext):
        """Returns ciphertext after verifying format prefix + hash + prefix + secret."""
        try:
            ciphertext.split(HASH_PREFIX.encode(ENCODING))[1]
            ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[1]
        except IndexError:
            ValueError('Malformed ciphertext. Expected prefixes {}, {}'.format(HASH_PREFIX, CIPHER_PREFIX))
        try:
            if ciphertext[:len(HASH_PREFIX)] != HASH_PREFIX.encode(ENCODING):
                raise MalformedCiphertextError('Malformed ciphertext. Expected hash prefix {}'.format(HASH_PREFIX))
            if (len(ciphertext.split(HASH_PREFIX.encode(ENCODING))[1].split(
                    CIPHER_PREFIX.encode(ENCODING))[0]) != self.hash_size):
                raise MalformedCiphertextError('Malformed ciphertext. Expected hash size of {}.'.format(self.hash_size))
        except IndexError:
            MalformedCiphertextError('Malformed ciphertext.')
        return ciphertext

    def get_prep_value(self, ciphertext, value):
        """ Gets the hash from encrypted value for the DB """
        if ciphertext != value:
            self.update_cipher_model(ciphertext)
        hashed_value = self.get_hash(ciphertext)
        return HASH_PREFIX.encode(ENCODING) + hashed_value

    def get_hash(self, ciphertext):
        """Returns the hashed_value given a ciphertext or None."""
        return ciphertext[len(HASH_PREFIX):][:self.hash_size] or None

    def get_secret(self, ciphertext, hashed_value):
        """ Returns the secret given a ciphertext and the hashed_value.

        ciphertext may be prefix + hashed_value OR
        ciphertext may be prefix + hashed_value + prefix + secret

        Searches in order: ciphertext, buffer, cipher model (Crypt)."""
        if ciphertext is None:
            secret = None
        else:
            if self.is_encrypted(ciphertext):
                # confirm given hash is in given ciphertext
                if hashed_value != ciphertext[len(HASH_PREFIX):][:self.hash_size]:
                    raise ValueError('Given hash not found in ciphertext!')
                # slice
                secret = ciphertext[len(HASH_PREFIX) + len(hashed_value) + len(CIPHER_PREFIX):]
                if not secret:
                    # look in buffer
                    secret = cipher_buffer.retrieve_secret(hashed_value)
                    if not secret:
                        # look in cipher model (Crypt)
                        try:
                            cipher_model = self.cipher_model.objects.values('secret').get(hash=hashed_value)
                            secret = cipher_model.get('secret')
                            cipher_buffer.append(hashed_value, secret)
                        except self.cipher_model.DoesNotExist:
                            pass
                if not secret:
                    raise EncryptionError(
                        'Could not retrieve a secret for given hash. Got {0}'.format(hashed_value))
            else:
                raise EncryptionError('Value must be encrypted or None.')
        return secret

    def is_encrypted(self, value):
        """Returns True if value is encrypted and formatted as 'ciphertext'; that is, if it starts
        with 'HASH_PREFIX'.

        Also assumes a value prefix by CIPHER_PREFIX is encrypted."""
        is_encrypted = False
        if value in [HASH_PREFIX, CIPHER_PREFIX]:
            raise MalformedCiphertextError('Expected a value, got just the encryption prefix.')
        if value[:len(HASH_PREFIX)] == HASH_PREFIX.encode(ENCODING):
            is_encrypted = True
        elif value[:len(CIPHER_PREFIX)] == CIPHER_PREFIX.encode(ENCODING):
            is_encrypted = True
        return is_encrypted

    def mask(self, value, mask='<encrypted>'):
        """ Returns 'mask' if value is encrypted."""
        if self.is_encrypted(value):
            return mask
        else:
            return value
