import logging

from django.db.models import get_model

from .cryptor import Cryptor
from classes import cipher_buffer
from classes.constants import KEY_FILENAMES, HASH_PREFIX, CIPHER_PREFIX, ENCODING

logger = logging.getLogger(__name__)


CipherModel = get_model('crypto_fields', 'crypt')


class FieldCryptor(object):
    """ Base class for django field classes with encryption.

    ciphertext = hash_prefix + hashed_value + cipher_prefix + secret
    """
    def __init__(self, algorithm, mode):
        self.algorithm = algorithm
        self.mode = mode
        self.cryptor = Cryptor()

    def encrypt(self, value):
        """ Returns ciphertext.

        For example: enc1:::234234ed234a24enc2::\x0e\xb9\xae\x13s\x8d\xe7O\xbb\r\x99"""
        if self.is_encrypted(value):
            ciphertext = value
        else:
            try:
                if self.algorithm == 'aes':
                    cipher = self.cryptor.aes_encrypt
                elif self.algorithm == 'rsa':
                    cipher = self.cryptor.rsa_encrypt
                else:
                    cipher = None
                ciphertext = (HASH_PREFIX.encode(ENCODING) + self.cryptor.hash(value, self.mode) +
                              CIPHER_PREFIX.encode(ENCODING) + cipher(value, self.mode))
            except AttributeError:
                raise AttributeError(
                    'Cannot determine cipher method. Unknown encryption algorithm. '
                    'Valid options are {0}. Got {1}'.format(', '.join(KEY_FILENAMES), self.algorithm))
        return ciphertext

    def decrypt(self, ciphertext):
        """ Decrypts secret and if secret is a hash, uses hash to lookup the real secret first.

        Do not assume secret is an encrypted value, look for HASH_PREFIX or secret prefix.
        By default we expect secret to be the stored field value -- which is a hash.
        If we use this method for a secret that is not a hash, then the prefix is
        the CIPHER_PREFIX and the lookup step is skipped. """
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
                        raise ValueError(
                            'Cannot determine algorithm for decryption.'
                            ' Valid options are {0}. Got {1}'.format(
                                ', '.join(list(KEY_FILENAMES)), self.algorithm))
                else:
                    hashed_value = self.get_hash(ciphertext)
                    if hashed_value:
                        raise ValueError(
                            'Failed to decrypt. Could not find "secret" '
                            ' for hash \'{0}\''.format(hashed_value))
                    else:
                        raise ValueError('Failed to decrypt. Malformed ciphertext')
        return plaintext or ciphertext

    def update_cipher_model(self, ciphertext):
        """ Updates cipher model (Crypt) and buffer."""
        if ciphertext:
            ciphertext = self.verify_ciphertext(ciphertext)
            hashed_value = self.get_hash(ciphertext)
            secret = self.get_secret(ciphertext, hashed_value)
            found = cipher_buffer.retrieve_secret(hashed_value)
            if not found:
                found = CipherModel.objects.filter(hash=hashed_value).exists()
            if found and secret:
                CipherModel.objects.filter(hash=hashed_value).update(secret=secret)
            elif secret:
                CipherModel.objects.create(
                    hash=hashed_value,
                    secret=secret,
                    algorithm=self.algorithm,
                    mode=self.mode)
            else:
                # if the hash is not in the crypt model and you do not have a secret
                # update: if performing a search, instead of data entry, the hash will not
                # exist, so this print should eventually be removed
                logger.warning(
                    'hash not found in crypt model. {0} {1} {2}'.format(
                        self.algorithm, self.mode, hashed_value))

    def verify_ciphertext(self, ciphertext):
        """Returns ciphertext after verifying format prefix + hash + prefix + secret."""
        try:
            ciphertext.split(HASH_PREFIX.encode(ENCODING))[1]
            ciphertext.split(CIPHER_PREFIX.encode(ENCODING))[1]
        except IndexError:
            ValueError('Malformed ciphertext. Expected prefixes {}, {}'.format(HASH_PREFIX, CIPHER_PREFIX))
        try:
            if ciphertext[:len(HASH_PREFIX)] != HASH_PREFIX.encode(ENCODING):
                raise ValueError('Malformed ciphertext. Expected hash prefix {}'.format(HASH_PREFIX))
            if (ciphertext.split(HASH_PREFIX.encode(ENCODING))[1].split(
                    CIPHER_PREFIX.encode(ENCODING))[0] != self.cryptor.hash_size):
                raise ValueError('Malformed ciphertext. Expected hash size of {}.'.format(self.cryptor.hash_size))
        except IndexError:
            ValueError('Malformed ciphertext.')
        return ciphertext

    def get_prep_value(self, ciphertext, value, update_cipher_model=None):
        """ Gets the hash from encrypted value for the DB """
        update_cipher_model = update_cipher_model or True
        if ciphertext != value:
            # encrypted_value is a hashed_value + secret, use this
            # to put the secret into the lookup for this hashed_value.
            if update_cipher_model:
                self.update_cipher_model(ciphertext)
        hashed_value = self.get_hash(ciphertext)
        return HASH_PREFIX.encode(ENCODING) + hashed_value

    def get_hash(self, ciphertext):
        """Returns the hashed_value given a ciphertext or None."""
        return ciphertext[len(HASH_PREFIX):][:self.cryptor.hash_size] or None

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
                if hashed_value != ciphertext[len(HASH_PREFIX):][:self.cryptor.hash_size]:
                    raise ValueError('Given hash not found in ciphertext!')
                # slice
                secret = ciphertext[len(HASH_PREFIX) + len(hashed_value) + len(CIPHER_PREFIX):]
                if not secret:
                    # look in buffer
                    secret = cipher_buffer.retrieve_secret(hashed_value)
                    if not secret:
                        # look in cipher model (Crypt)
                        try:
                            cipher_model = CipherModel.objects.values('secret').get(hash=hashed_value)
                            secret = cipher_model.get('secret')
                            cipher_buffer.append(hashed_value, secret)
                        except CipherModel.DoesNotExist:
                            pass
                if not secret:
                    raise ValueError(
                        'Could not retrieve a secret for given hash. Got {0}'.format(hashed_value))
            else:
                raise ValueError('Value must be encrypted or None.')
        return secret

    def is_encrypted(self, value):
        """ Determines that a string value is encrypted if it starts
        with 'HASH_PREFIX' or CIPHER_PREFIX."""
        if value in [HASH_PREFIX, CIPHER_PREFIX]:
            raise TypeError('Expected a value, got just the encryption prefix.')
        is_encrypted = False
        if value[:len(HASH_PREFIX)] == HASH_PREFIX.encode(ENCODING):
            is_encrypted = True
        elif value[:len(CIPHER_PREFIX)] == CIPHER_PREFIX.encode(ENCODING):
            is_encrypted = True
        return is_encrypted

    def mask(self, value, mask='<encrypted>'):
        """ Help format values for display by masking them if encrypted
        at the time of display."""
        if self.is_encrypted(value):
            return mask
        else:
            return value
