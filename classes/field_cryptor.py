import logging

from django.db.models import get_model

from .cryptor import Cryptor
from .last_secret import last_secret
from classes.constants import KEY_FILENAMES, HASH_PREFIX, CIPHER_PREFIX

logger = logging.getLogger(__name__)


class FieldCryptor(object):
    """ Subclass to be used with models that expect to stored just the hash and for this class to handle the secret. """
    def __init__(self, algorithm, mode):
        self.algorithm = algorithm
        self.mode = mode
        self.cryptor = Cryptor()

    def encrypt(self, value):
        """ Returns the encrypted field value (prefix+hash+prefix+ciphertext).

        For example: enc1:::234234ed234a24enc2::h8d3dhdkb&^bn//e#"""
        if not self.is_encrypted(value):
            if self.algorithm == 'aes':
                cipher = self.cryptor.aes_encrypt
            elif self.algorithm == 'rsa':
                cipher = self.cryptor.rsa_encrypt
            else:
                raise ValueError(
                    'Unknown encryption algorithm. Valid options are {0}. '
                    'Got {1}'.format(', '.join(KEY_FILENAMES), self.algorithm))
            value = HASH_PREFIX + self.hash(value) + CIPHER_PREFIX + cipher(value, self.mode)
        return value

    def decrypt(self, ciphertext, secret_is_hash=True, **kwargs):
        """ Decrypts secret and if secret is a hash, uses hash to lookup the real secret first.

        Do not assume secret is an encrypted value, look for HASH_PREFIX or secret prefix.
        By default we expect secret to be the stored field value -- which is a hash.
        If we use this method for a secret that is not a hash, then the prefix is
        the CIPHER_PREFIX and the lookup step is skipped. """

        plaintext = ciphertext
        if ciphertext:
            if secret_is_hash:
                prefix = HASH_PREFIX
            else:
                prefix = CIPHER_PREFIX
            if self.is_encrypted(ciphertext, prefix):
                if secret_is_hash:
                    hashed_value = self.hash(ciphertext)
                    secret = self._get_secret_from_hash_secret(ciphertext, hashed_value)
                else:
                    secret = secret[len(self.cryptor.CIPHER_PREFIX):]  # secret is not a hash
                if secret:
                    if self.algorithm == 'aes':
                        if self.cryptor.set_aes_key():
                            plaintext = self.cryptor.aes_decrypt(secret.partition(self.cryptor.IV_PREFIX))
                    elif self.algorithm == 'rsa':
                        if self.cryptor.set_private_key():
                            plaintext = self.cryptor.rsa_decrypt(secret)
                    else:
                        raise ValueError('Cannot determine algorithm for decryption.'
                                         ' Valid options are {0}. Got {1}'.format(', '.join(list(self.cryptor.VALID_MODES.keys())),
                                                                                  self.algorithm))
                else:
                    raise ValueError('When decrypting from hash, could not find secret'
                                     ' in lookup for hash {0}'.format(hashed_value))
        return plaintext

    def update_secret_in_lookup(self, hash_secret):
        """ Updates lookup with hashed_value and secret pairs given a hash+secret string."""
        hashed_value = None
        if hash_secret:
            # get and update or create the crypt model with this hash, cipher pair
            Crypt = get_model('crypto_fields', 'crypt')
            hashed_value = self.hash(hash_secret)
            secret = self._get_secret_from_hash_secret(hash_secret, hashed_value)
            found = last_secret.get(hashed_value) is not None
            if not found:
                found = Crypt.objects.filter(hash=hashed_value).exists()
            if found:
                if secret:
                    Crypt.objects.filter(hash=hashed_value).update(secret=secret)
#                     crypt = Crypt.objects.get(hash=hashed_value)
#                     crypt.secret = secret
#                     crypt.save()
            else:
                if secret:
                    Crypt.objects.create(hash=hashed_value,
                                         secret=secret,
                                         algorithm=self.algorithm,
                                         mode=self.mode)
                else:
                    # if the hash is not in the crypt model and you do not have a secret
                    # update: if performing a search, instead of data entry, the hash will not
                    # exist, so this print should eventually be removed
                    logger.warning('hash not found in crypt model. {0} {1} {2}'.format(self.algorithm, self.mode, hashed_value))

    def hash(self, value):
        """ Returns a hashed value without hash_prefix by either
        splitting it from value or hashing the value.

        If value is an encrypted value string, split to get hashed_value
        segment (less hash_prefix and secret)
        """
        if self.is_encrypted(value):
            hashed_value = value[len(HASH_PREFIX):][:self.cryptor.hash_size]
        else:
            hashed_value = self.cryptor.hash(value, self.mode)
        return hashed_value

    def get_prep_value(self, encrypted_value, value, **kwargs):
        """ Gets the hash from encrypted value for the DB """
        update_lookup = kwargs.get('update_lookup', True)
        if encrypted_value != value:
            # encrypted_value is a hashed_value + secret, use this to put the secret into the lookup for this hashed_value.
            if update_lookup:
                self.update_secret_in_lookup(encrypted_value)
        hashed_value = self.hash(encrypted_value)
        return self.cryptor.HASH_PREFIX + hashed_value

    def _get_secret_from_hash_secret(self, value, hashed_value):
        """ Returns the secret by splitting value on the hashed_value if value is hash+secret otherwise value is the prefix+hashed_value. """
        if not value:
            retval = None
        else:
            if self.is_encrypted(value):
                # split on hash, but if this is a hash only, secret_string will be None
                secret = value[len(self.cryptor.HASH_PREFIX) + len(hashed_value) + len(self.cryptor.CIPHER_PREFIX):]
                if not secret:
                    # lookup secret_string for this hashed_value
                    secret = self._lookup_secret(hashed_value)
                    if not secret:
                        raise ValueError('Could not retrieve a secret for given hash. Got {0}'.format(hashed_value))
                retval = secret
            else:
                raise ValueError('Value must be encrypted or None.')
        return retval

    def _lookup_secret(self, hashed_value):
        """ Looks up a secret for hashed+value in the Crypt model.

        If not found, returns None"""
        secret = last_secret.get(hashed_value)
        if not secret:
            Crypt = get_model('crypto_fields', 'crypt')
            try:
                # TODO: this ignores "using" which is a serious problem
                # for working with multiple databases
                crypt = Crypt.objects.values('secret').get(hash=hashed_value)
                secret = crypt.get('secret')
                last_secret.set(hashed_value, secret)
            except Crypt.DoesNotExist:
                pass
        return secret

    def is_encrypted(self, value):
        """ Determines that a value string is encrypted if it starts
        with 'HASH_PREFIX' or whichever prefix is passed."""
        if value == HASH_PREFIX:
            raise TypeError('Expected a value, got just the encryption prefix.')
        try:
            is_encrypted = True if value.startswith(HASH_PREFIX) else False
        except AttributeError:
            is_encrypted = False
        return is_encrypted

    def mask(self, value, mask='<encrypted>'):
        """ Help format values for display by masking them if encrypted
        at the time of display."""
        if self.is_encrypted(value):
            return mask
        else:
            return value

