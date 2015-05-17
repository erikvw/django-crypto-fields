import copy
import sys

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number

from ..constants import KEY_FILENAMES, KEY_PATH, KEY_PREFIX
from ..utils import KeyGenerator

KEYS = copy.deepcopy(KEY_FILENAMES)


class Keys(object):

    def __init__(self):
        self.loaded = False
        self.rsa_key_info = {}
        try:
            self.load_keys()
        except FileNotFoundError:
            sys.stdout.write('/* Loading keys failed.\n')
            KeyGenerator.create_keys(KEY_PATH, KEY_PREFIX, show_msgs=False)
            self.load_keys()

    def load_rsa_key(self, mode, key):
        """Loads an RSA key."""
        key_file = KEY_FILENAMES['rsa'][mode][key]
        with open(key_file, 'rb') as frsa:
            rsa_key = RSA.importKey(frsa.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            KEYS['rsa'][mode][key] = rsa_key
            self.update_rsa_key_info(rsa_key, mode)
        return key_file

    def load_aes_key(self, mode, key):
        """Decrypts and loads an AES key."""
        rsa_key = KEYS['rsa'][mode]['private']
        key_file = KEY_FILENAMES['aes'][mode]['private']
        with open(key_file, 'rb') as faes:
            aes_key = rsa_key.decrypt(faes.read())
        KEYS['aes'][mode]['private'] = aes_key
        return key_file

    def load_salt_key(self, mode, key):
        """Decrypts and loads a salt key."""
        rsa_key = KEYS['rsa'][mode]['private']
        key_file = KEY_FILENAMES['salt'][mode]['private']
        with open(key_file, 'rb') as fsalt:
            salt = rsa_key.decrypt(fsalt.read())
        KEYS['salt'][mode]['private'] = salt
        return key_file

    def load_keys(self):
        sys.stdout.write('/* Loading keys ...\n')
        for mode, keys in KEY_FILENAMES['rsa'].items():
            for key in keys:
                key_file = self.load_rsa_key(mode, key)
                sys.stdout.write('(*) Loaded {}\n'.format(key_file))
        for mode in KEY_FILENAMES['aes']:
            key_file = self.load_aes_key(mode, key)
            sys.stdout.write('(*) Loaded {}\n'.format(key_file))
        for mode in KEY_FILENAMES['salt']:
            key_file = self.load_salt_key(mode, key)
            sys.stdout.write('(*) Loaded {}\n'.format(key_file))
        sys.stdout.write('Done loading keys.\n')
        self.loaded = True

    def update_rsa_key_info(self, rsa_key, mode):
        """Stores info about the RSA key."""
        modBits = number.size(rsa_key._key.n)
        self.rsa_key_info[mode] = {'bits': modBits}
        k = number.ceil_div(modBits, 8)
        self.rsa_key_info[mode].update({'bytes': k})
        hLen = rsa_key._hashObj.digest_size
        self.rsa_key_info[mode].update({'max_message_length': k - (2 * hLen) - 2})

keys = Keys()
