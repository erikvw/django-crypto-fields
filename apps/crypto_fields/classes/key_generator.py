from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from .constants import KEY_FILENAMES, RSA_KEY_SIZE


class KeyGenerator(object):
    """Generates RSA and AES keys as per the KEY_FILENAME dictionary.

    KEY_FILENAME names the algorithm (rsa, aes or salt), the mode (local,
    restricted and irreversible) and the paths of the files to be created.

    Existing files will not be overwritten.

    The default KEY_FILENAME dictionary refers to 7 files.
        - 2 RSA local (public, private)
        - 2 RSA restricted  (public, private)
        - 1 RSA irreversible  (public only)
        - 1 AES local (RSA encrypted)
        - 1 salt local (RSA encrypted)."""

    @classmethod
    def create_keys(cls):
        """Creates all keys referred to in the KEY_FILENAME dictionary."""
        cls.create_rsa()
        cls.create_aes()
        cls.create_salt()

    @classmethod
    def create_rsa(cls):
        """Creates RSA keys."""
        for mode in KEY_FILENAMES.get('rsa'):
            key = RSA.generate(RSA_KEY_SIZE)
            pub = key.publickey()
            path = KEY_FILENAMES.get('rsa').get(mode).get('public')
            with open(path, 'xb') as fpub:
                fpub.write(pub.exportKey('PEM'))
            print('(*) Created new RSA {0} key {1}'.format(mode, path))
            try:
                path = KEY_FILENAMES.get('rsa').get(mode).get('private')
                with open(path, 'xb') as fpub:
                    fpub.write(key.exportKey('PEM'))
                print('(*) Created new RSA {0} key {1}'.format(mode, path))
            except TypeError:
                pass

    @classmethod
    def create_aes(cls):
        """Creates AES keys and RSA encrypts them."""
        for mode in KEY_FILENAMES.get('aes'):
            with open(KEY_FILENAMES.get('rsa').get(mode).get('public'), 'rb') as rsa_file:
                rsa_key = RSA.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            aes_key = Random.new().read(16)
            key_file = KEY_FILENAMES.get('aes').get(mode).get('private')
            with open(key_file, 'xb') as faes:
                faes.write(rsa_key.encrypt(aes_key))
            print('(*) Created new AES {0} key {1}'.format(mode, key_file))

    @classmethod
    def create_salt(cls):
        """Creates a salt and RSA encrypts it."""
        mode = 'local'
        with open(KEY_FILENAMES.get('rsa').get(mode).get('public'), 'rb') as rsa_file:
            rsa_key = RSA.importKey(rsa_file.read())
        rsa_key = PKCS1_OAEP.new(rsa_key)
        salt = Random.new().read(8)
        key_file = KEY_FILENAMES.get('salt').get(mode).get('private')
        with open(key_file, 'xb') as fsalt:
            fsalt.write(rsa_key.encrypt(salt))
        print('(*) Created new salt local key {0}'.format(key_file))
