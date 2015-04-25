import os
import base64
from M2Crypto import Rand, RSA
from django.conf import settings
from .cryptor import Cryptor


class KeyGenerator(object):

    def create_new_keys(self):
        self._create_new_rsa_key_pairs()
        self._create_new_aes_keys()
        self._create_new_salts()
        self.test_keys()
        if self.load_success:
            print 'New keys are stored in \'{0}\''.format(settings.KEY_PATH)

    def test_keys(self):
        """ Tests keys """
        for algorithm, mode_dict in Cryptor._VALID_MODES.iteritems():
            for mode in mode_dict.iterkeys():
                cryptor = Cryptor(algorithm, mode, preload=False)
                self.load_success = cryptor.preload_all_keys()
                break
            break

    def get_key_paths(self):
        """ Returns a list of key pathnames """
        paths = []
        for algorithm, mode_dict in Cryptor._VALID_MODES.iteritems():
            for mode, key_dict in mode_dict.iteritems():
                for key_name in key_dict.iterkeys():
                    if Cryptor._VALID_MODES.get(algorithm).get(mode).get(key_name):
                        paths.append(Cryptor._VALID_MODES.get(algorithm).get(mode).get(key_name))
        return paths

    def _create_new_aes_keys(self, key=None):
        """ Creates a new key and stores it safely in a file by using rsa encryption for the mode.

        Filename suffix is added to the filename to avoid overwriting an
        existing key """
        algorithm = 'aes'
        for mode in Cryptor._VALID_MODES.get(algorithm).iterkeys():
            if not key:
                key = os.urandom(16)
            path = Cryptor._VALID_MODES.get(algorithm).get(mode).get('key')
            cryptor = Cryptor(algorithm, mode, preload=False)
            encrypted_aes = cryptor._encrypt_aes_key(key, mode)
            del cryptor
            if os.path.exists(path):
                print ('( ) Failed to create new {0} {1} key. File exists. {2}'.format(algorithm, mode, path))
            else:
                f = open(path, 'w')
                f.write(base64.b64encode(encrypted_aes))
                f.close()
                print '(*) Created new {0} {1} key {2}'.format(algorithm, mode, path)

    def _create_new_rsa_key_pairs(self):
        """ Creates a new rsa key-pair. """

        def _blank_callback(self):
            "Replace the default dashes as output upon key generation"
            return
        algorithm = 'rsa'
        for mode, key_pair in Cryptor._VALID_MODES.get(algorithm).iteritems():
            # Random seed
            Rand.rand_seed(os.urandom(Cryptor.RSA_KEY_LENGTH))
            # Generate key pair
            key = RSA.gen_key(Cryptor.RSA_KEY_LENGTH, 65537, _blank_callback)
            # create and save the public key to file
            filename = key_pair.get('public', None)
            if key.save_pub_key(''.join(filename)) > 0:
                print '(*) Created new {0} {1} {2}'.format(algorithm, mode, filename)
            else:
                print '( ) Failed to create new {0} {1} {2}'.format(algorithm, mode, filename)
            # create and save the private key to file
            filename = key_pair.get('private', None)
            # key.save_key('user-private-local.pem'), e.g if suffix=''
            if filename:
                if key.save_key(''.join(filename), None) > 0:
                    print '(*) Created new {0} {1} key {2}'.format(algorithm, mode, filename)
                else:
                    print '( ) Failed to create new {0} {1} key {2}'.format(algorithm, mode, filename)

    def _create_new_salts(self, length=12,
                        allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*()?<>.,[]{}'):
        """ Creates a new salt and encrypts it with the \'salter\' rsa public key.

        Algorithm and mode are needed to get the filename from VAILD_MODES.
        """
        # create a salt for each algorithm and mode
        for algorithm, mode_dict in Cryptor._VALID_MODES.iteritems():
            for mode in mode_dict.iterkeys():
                if Cryptor._VALID_MODES.get(algorithm).get(mode).get('salt'):
                    path = Cryptor._VALID_MODES.get(algorithm).get(mode).get('salt')
                    cryptor = Cryptor(algorithm, mode, preload=False)
                    salt = cryptor._encrypt_salt(cryptor.make_random_salt(length, allowed_chars))
                    del cryptor
                    f = open(path, 'w')
                    f.write(base64.b64encode(salt))
                    f.close()
                    print '(*) Created new {0} {1} salt {2}'.format(algorithm, mode, path)
