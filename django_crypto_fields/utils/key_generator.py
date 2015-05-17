import os
import sys

from copy import deepcopy

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from ..constants import KEY_FILENAMES, RSA_KEY_SIZE, KEY_PATH, KEY_PREFIX


class KeyGenerator(object):
    """Generates RSA and AES keys as per the KEY_FILENAME dictionary.

    KEY_FILENAME names the algorithm (rsa, aes or salt), the mode (local and
    restricted) and the paths of the files to be created.

    Existing files will not be overwritten.

    The default KEY_FILENAME dictionary refers to 8 files.
        - 2 RSA local (public, private)
        - 2 RSA restricted  (public, private)
        - 1 AES local (RSA encrypted)
        - 1 AES restricted (RSA encrypted)
        - 1 salt local (RSA encrypted).
        - 1 salt restricted (RSA encrypted)."""

    key_filenames = deepcopy(KEY_FILENAMES)

    @classmethod
    def replace_path(cls, path, show_msgs=None):
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            raise FileNotFoundError('Path {} does not exist'.format(path))
        for algorithm in cls.key_filenames:
            for mode in cls.key_filenames[algorithm]:
                for key in cls.key_filenames[algorithm][mode]:
                    cls.key_filenames[algorithm][mode][key] = (
                        cls.key_filenames[algorithm][mode][key].replace(KEY_PATH + '/', ''))
                    cls.key_filenames[algorithm][mode][key] = (
                        os.path.join(path, cls.key_filenames[algorithm][mode][key]))
        if show_msgs:
            sys.stdout.write('Warning! Keys will be written to a custom path. Using \'{}\'\n'.format(path))

    @classmethod
    def replace_prefix(cls, prefix, show_msgs=None):
        for algorithm in cls.key_filenames:
            for mode in cls.key_filenames[algorithm]:
                for key in cls.key_filenames[algorithm][mode]:
                    cls.key_filenames[algorithm][mode][key] = (
                        cls.key_filenames[algorithm][mode][key].replace('/' + KEY_PREFIX + '-', '/' + prefix + '-'))
        if show_msgs:
            sys.stdout.write('Warning! Keys will be named with a custom prefix. Using \'{}\'\n'.format(prefix))

    @classmethod
    def create_keys(cls, path=None, prefix=None, show_msgs=None):
        """Creates all keys referred to in the KEY_FILENAME dictionary."""
        sys.stdout.write('/* Creating keys ...\n')
        show_msgs = True if show_msgs is None else show_msgs
        if prefix:
            cls.replace_prefix(prefix, show_msgs=show_msgs)
        if path:
            path = os.path.expanduser(path)
            cls.replace_path(path, show_msgs=show_msgs)
        cls.create_rsa(show_msgs=show_msgs)
        cls.create_aes(show_msgs=show_msgs)
        cls.create_salt(show_msgs=show_msgs)
        sys.stdout.write('/* Done creating keys.\n')

    @classmethod
    def create_rsa(cls, mode=None, show_msgs=None):
        """Creates RSA keys."""
        modes = [mode] if mode else cls.key_filenames.get('rsa')
        for mode in modes:
            key = RSA.generate(RSA_KEY_SIZE)
            pub = key.publickey()
            path = cls.key_filenames.get('rsa').get(mode).get('public')
            with open(path, 'xb') as fpub:
                fpub.write(pub.exportKey('PEM'))
            if show_msgs:
                sys.stdout.write('(*) Created new RSA {0} key {1}\n'.format(mode, path))
            try:
                path = cls.key_filenames.get('rsa').get(mode).get('private')
                with open(path, 'xb') as fpub:
                    fpub.write(key.exportKey('PEM'))
                if show_msgs:
                    sys.stdout.write('(*) Created new RSA {0} key {1}\n'.format(mode, path))
            except TypeError:
                pass

    @classmethod
    def create_aes(cls, mode=None, show_msgs=None):
        """Creates AES keys and RSA encrypts them."""
        modes = [mode] if mode else cls.key_filenames.get('aes')
        for mode in modes:
            with open(cls.key_filenames.get('rsa').get(mode).get('public'), 'rb') as rsa_file:
                rsa_key = RSA.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            aes_key = Random.new().read(16)
            key_file = cls.key_filenames.get('aes').get(mode).get('private')
            with open(key_file, 'xb') as faes:
                faes.write(rsa_key.encrypt(aes_key))
            if show_msgs:
                sys.stdout.write('(*) Created new AES {0} key {1}\n'.format(mode, key_file))

    @classmethod
    def create_salt(cls, mode=None, show_msgs=None):
        """Creates a salt and RSA encrypts it."""
        modes = [mode] if mode else cls.key_filenames.get('salt')
        for mode in modes:
            with open(cls.key_filenames.get('rsa').get(mode).get('public'), 'rb') as rsa_file:
                rsa_key = RSA.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            salt = Random.new().read(8)
            key_file = cls.key_filenames.get('salt').get(mode).get('private')
            with open(key_file, 'xb') as fsalt:
                fsalt.write(rsa_key.encrypt(salt))
            if show_msgs:
                sys.stdout.write('(*) Created new salt {0} key {1}\n'.format(mode, key_file))
