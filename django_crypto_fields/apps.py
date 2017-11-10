import sys

from Crypto.Cipher import AES
from django.apps import AppConfig as DjangoAppConfig
from django.conf import settings
from django.core.management.color import color_style

from .cryptor import Cryptor
from .exceptions import EncryptionError
from .key_creator import KeyCreator
from .key_files import KeyFiles
from .keys import Keys


class DjangoCryptoFieldsError(Exception):
    pass


style = color_style()


class AppConfig(DjangoAppConfig):
    name = 'django_crypto_fields'
    verbose_name = "Data Encryption"
    encryption_keys = None
    app_label = 'django_crypto_fields'
    model = 'django_crypto_fields.crypt'
    # change if using more than one database and not 'default'.
    crypt_model_using = 'default'
    temp_path = None
    try:
        auto_create_keys = settings.DEBUG and settings.AUTO_CREATE_KEYS
    except AttributeError:
        auto_create_keys = False

    def __init__(self, app_label, model_name):
        """Placed here instead of `ready()`. For models to
        load correctly that use field classes from this module the keys
        need to be loaded before models.
        """
        super().__init__(app_label, model_name)

        key_files = KeyFiles()
        if not self.encryption_keys:
            sys.stdout.write(f'Loading {self.verbose_name} ...\n')
            if not key_files.key_files_exist:
                sys.stdout.write(style.WARNING(
                    f'{self.verbose_name} failed to find any encryption keys.\n'))
                sys.stdout.write(
                    '  Confirm that settings.KEY_PATH points to the correct folder.\n')
                sys.stdout.write(
                    '  Loading the wrong encryption keys can corrupt sensitive data.\n')
                sys.stdout.write(
                    '  If this is your first time loading the project, '
                    '  new keys will be generated\n')
                sys.stdout.write(
                    '  and placed in the settings.KEY_PATH folder.\n')
                if self.auto_create_keys:
                    sys.stdout.write(style.SUCCESS(
                        f'  * settings.AUTO_CREATE_KEYS={self.auto_create_keys}.\n'))
                    key_creator = KeyCreator()
                    key_creator.create_keys()
                    self.temp_path = key_creator.temp_path
                else:
                    raise EncryptionError('Encryption keys not found.')
            else:
                sys.stdout.write(
                    f' * found encryption keys in {key_files.key_path}.\n')
            keys = Keys()
            keys.load_keys()
            self.encryption_keys = keys
            sys.stdout.write(
                f' * using model {self.app_label}.crypt.\n')
            sys.stdout.write(f' Done loading {self.verbose_name}.\n')
            sys.stdout.flush()

    def ready(self):
        cryptor = Cryptor()
        if cryptor.aes_encryption_mode == AES.MODE_CFB:
            sys.stdout.write(style.NOTICE(
                'Warning: Encryption mode MODE_CFB should not be used. \n'
                '         See django_crypto_fields.cryptor.py and comments \n'
                '         in pycrypto.blockalgo.py.\n'))
            sys.stdout.flush()

#     @property
#     def model_cls(self):
#         return django_apps.get_model(self.model)
