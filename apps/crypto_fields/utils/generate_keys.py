import os

from apps.crypto_fields.classes import KeyGenerator
from apps.crypto_fields.classes.constants import KEY_PATH


def generate_keys():
    """ Utility to generate all new keys for the project."""
    key_generator = KeyGenerator()
    try:
        key_generator.create_keys()
        print('Complete.')
    except (FileExistsError):
        print('Failed. Keys already exist in target folder \'{}\'.'.format(KEY_PATH))

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    generate_keys()
