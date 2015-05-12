import os

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


RSA_KEY_SIZE = 2048
ENCODING = 'utf-8'
HASH_ALGORITHM = 'sha256'
HASH_ROUNDS = 100000
HASH_PREFIX = b'enc1:::'
CIPHER_PREFIX = b'enc2:::'

try:
    prefix = settings.PROJECT_NUMBER
except (ImproperlyConfigured, AttributeError) as e:
    prefix = 'user'

try:
    KEY_PATH = settings.KEY_PATH
except (ImproperlyConfigured, AttributeError) as e:
    KEY_PATH = os.path.expanduser('~/')
    prefix = 'test'
    print('Warning! Not ready for production. {}. Setting KEY_PATH to {} for testing purposes.'.format(e, KEY_PATH))

KEY_FILENAMES = {
    # algorithm : {mode: {key:path}}
    'rsa': {
        'irreversible': {
            'public': os.path.join(KEY_PATH, prefix + '-rsa-irreversible-public.pem')},
        'restricted': {
            'public': os.path.join(KEY_PATH, prefix + '-rsa-restricted-public.pem'),
            'private': os.path.join(KEY_PATH, prefix + '-rsa-restricted-private.pem')},
        'local': {
            'public': os.path.join(KEY_PATH, prefix + '-rsa-local-public.pem'),
            'private': os.path.join(KEY_PATH, prefix + '-rsa-local-private.pem')}},
    'aes': {
        'local': {
            'private': os.path.join(KEY_PATH, prefix + '-aes-local.key')}},
    'salt': {
        'local': {
            'private': os.path.join(KEY_PATH, prefix + '-salt-local.key')}},
}
