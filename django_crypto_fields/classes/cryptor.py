import copy
import logging

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util import number

from ..constants import KEY_FILENAMES, ENCODING
from ..exceptions import EncryptionError

logger = logging.getLogger(__name__)


class NullHandler(logging.Handler):
    def emit(self, record):
        pass
nullhandler = logger.addHandler(NullHandler())


class Cryptor(object):
    """Base class for all classes providing RSA and AES encryption methods.

    The PEM file names and paths are in KEY_FILENAMES. KEYS is a copy of this except the
    filenames are replaced with the actual keys."""

    KEYS = copy.deepcopy(KEY_FILENAMES)

    def __init__(self):
        self.rsa_key_info = {}
        self.load_keys()

    def aes_encrypt(self, plaintext, mode):
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        aes_key = self.KEYS.get('aes').get(mode).get('private')
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(plaintext)

    def aes_decrypt(self, ciphertext, mode):
        aes_key = self.KEYS.get('aes').get(mode).get('private')
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)[AES.block_size:]
        return plaintext.decode(ENCODING)

    def rsa_encrypt(self, plaintext, mode):
        rsa_key = self.KEYS.get('rsa').get(mode).get('public')
        try:
            plaintext = plaintext.encode(ENCODING)
        except AttributeError:
            pass
        try:
            ciphertext = rsa_key.encrypt(plaintext)
        except (ValueError, TypeError) as e:
            raise EncryptionError('RSA encryption failed for value. Got \'{}\''.format(e))
        return ciphertext

    def rsa_decrypt(self, ciphertext, mode):
        rsa_key = self.KEYS.get('rsa').get(mode).get('private')
        plaintext = rsa_key.decrypt(ciphertext)
        return plaintext.decode(ENCODING)

    def update_rsa_key_info(self, rsa_key, mode):
        """Stores info about the RSA key."""
        modBits = number.size(rsa_key._key.n)
        self.rsa_key_info[mode] = {'bits': modBits}
        k = number.ceil_div(modBits, 8)
        self.rsa_key_info[mode].update({'bytes': k})
        hLen = rsa_key._hashObj.digest_size
        self.rsa_key_info[mode].update({'max_message_length': k - (2 * hLen) - 2})

    def load_keys(self):
        logger.info('/* Loading keys ...')
        try:
            # load RSA
            for mode, keys in KEY_FILENAMES['rsa'].items():
                for key in keys:
                    key_file = KEY_FILENAMES['rsa'][mode][key]
                    with open(key_file, 'rb') as f:
                        rsa_key = RSA.importKey(f.read())
                        rsa_key = PKCS1_OAEP.new(rsa_key)
                        self.KEYS['rsa'][mode][key] = rsa_key
                        self.update_rsa_key_info(rsa_key, mode)
                    logger.info('(*) Loaded ' + key_file)
            # decrypt and load AES
            for mode in KEY_FILENAMES['aes']:
                rsa_key = self.KEYS['rsa'][mode]['private']
                key_file = KEY_FILENAMES['aes'][mode]['private']
                with open(key_file, 'rb') as faes:
                    aes_key = rsa_key.decrypt(faes.read())
                self.KEYS['aes'][mode]['private'] = aes_key
                logger.info('(*) Loaded ' + key_file)
            # decrypt and load salt
            for mode in KEY_FILENAMES['salt']:
                rsa_key = self.KEYS['rsa'][mode]['private']
                key_file = KEY_FILENAMES['salt'][mode]['private']
                with open(key_file, 'rb') as fsalt:
                    salt = rsa_key.decrypt(fsalt.read())
                self.KEYS['salt'][mode]['private'] = salt
                logger.info('(*) Loaded ' + key_file)
            logger.info('Done preloading keys. */')
        except FileNotFoundError:
            raise FileNotFoundError(
                'Unable to find keys. Check the KEY_PATH or, '
                'if you do not have any keys, run the \'generate_keys\' management command '
                'and try again.')

    def test_rsa(self):
        """ Tests keys roundtrip"""
        plaintext = 'erik is a pleeb!'
        for mode in KEY_FILENAMES.get('rsa'):
            try:
                rsa_key = self.KEYS.get('rsa').get(mode).get('public')
                ciphertext = rsa_key.encrypt(plaintext.encode('utf_8'))
                print('(*) Passed encrypt: ' + KEY_FILENAMES.get('rsa').get(mode).get('public'))
            except (AttributeError, TypeError) as e:
                print('( ) Failed encrypt: {} public ({})'.format(mode, e))
            try:
                rsa_key = self.KEYS.get('rsa').get(mode).get('private')
                assert plaintext == rsa_key.decrypt(ciphertext).decode(ENCODING)
                print('(*) Passed decrypt: ' + KEY_FILENAMES.get('rsa').get(mode).get('private'))
            except (AttributeError, TypeError) as e:
                print('( ) Failed decrypt: {} private ({})'.format(mode, e))

    def test_aes(self):
        """ Tests keys roundtrip"""
        plaintext = 'erik is a pleeb!'
        for mode in KEY_FILENAMES.get('aes'):
            ciphertext = self.aes_encrypt(plaintext, mode)
            assert plaintext != ciphertext
            print('(*) Passed encrypt: ' + KEY_FILENAMES.get('aes').get(mode).get('private'))
            assert plaintext == self.aes_decrypt(ciphertext, mode)
            print('(*) Passed decrypt: ' + KEY_FILENAMES.get('aes').get(mode).get('private'))
