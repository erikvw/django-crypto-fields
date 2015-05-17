import os

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


RSA_KEY_SIZE = 2048
ENCODING = 'utf-8'
HASH_ALGORITHM = 'sha256'
HASH_ROUNDS = 100000
HASH_PREFIX = 'enc1:::'
CIPHER_PREFIX = 'enc2:::'
CIPHER_BUFFER_SIZE = 10

try:
    KEY_PREFIX = settings.KEY_PREFIX
except (ImproperlyConfigured, AttributeError) as e:
    KEY_PREFIX = 'user'

try:
    KEY_PATH = settings.KEY_PATH
except (ImproperlyConfigured, AttributeError) as e:
    KEY_PATH = os.path.join(settings.BASE_DIR, 'django_crypto_fields/tests')
    KEY_PREFIX = 'test'
    print('Warning! Not ready for production. {}. Setting KEY_PATH to {} for testing purposes.'.format(e, KEY_PATH))

KEY_FILENAMES = {
    # algorithm : {mode: {key:path}}
    'rsa': {
        'restricted': {
            'public': os.path.join(KEY_PATH, KEY_PREFIX + '-rsa-restricted-public.pem'),
            'private': os.path.join(KEY_PATH, KEY_PREFIX + '-rsa-restricted-private.pem')},
        'local': {
            'public': os.path.join(KEY_PATH, KEY_PREFIX + '-rsa-local-public.pem'),
            'private': os.path.join(KEY_PATH, KEY_PREFIX + '-rsa-local-private.pem')}},
    'aes': {
        'local': {
            'private': os.path.join(KEY_PATH, KEY_PREFIX + '-aes-local.key')},
        'restricted': {
            'private': os.path.join(KEY_PATH, KEY_PREFIX + '-aes-restricted.key')}},
    'salt': {
        'local': {
            'private': os.path.join(KEY_PATH, KEY_PREFIX + '-salt-local.key')},
        'restricted': {
            'private': os.path.join(KEY_PATH, KEY_PREFIX + '-salt-restricted.key')}},
}
