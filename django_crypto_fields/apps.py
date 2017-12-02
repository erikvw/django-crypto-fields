import sys

from Crypto.Cipher import AES
from django.apps import AppConfig as DjangoAppConfig, apps as django_apps
from django.core.exceptions import AppRegistryNotReady
from django.conf import settings
from django.core.management.color import color_style

from .cryptor import Cryptor
from .exceptions import EncryptionError
from .key_creator import KeyCreator
from .key_files import KeyFiles
from .keys import Keys
from .key_path import DjangoCryptoFieldsKeyPathChangeError


class DjangoCryptoFieldsError(Exception):
    pass


style = color_style()


class AppConfig(DjangoAppConfig):
    name = 'django_crypto_fields'
    verbose_name = "Data Encryption"
    _keys = None
    _key_path_validated = None
    app_label = 'django_crypto_fields'
    model = 'django_crypto_fields.crypt'
    key_reference_model = 'django_crypto_fields.keyreference'
    # change if using more than one database and not 'default'.
    crypt_model_using = 'default'
    temp_path = None

    temp_key_commands = ['test', 'makemigrations', 'migrate', 'check']

    try:
        auto_create_keys = 'test' in sys.argv or (
            settings.DEBUG and settings.AUTO_CREATE_KEYS)
    except AttributeError:
        auto_create_keys = False

    def __init__(self, app_label, model_name):
        """Placed here instead of `ready()`. For models to
        load correctly that use field classes from this module the keys
        need to be loaded before models.
        """
        self.app_Loaded = False
        super().__init__(app_label, model_name)
        self.is_temp_command = [
            command for command in sys.argv if command in self.temp_key_commands]

        key_files = KeyFiles(
            use_temp_path=self.is_temp_command)
        if not self._keys:
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
                if self.auto_create_keys or self.is_temp_command:
                    sys.stdout.write(style.SUCCESS(
                        f'  * settings.AUTO_CREATE_KEYS={self.auto_create_keys}.\n'))
                    key_creator = KeyCreator(
                        use_temp_path=self.is_temp_command)
                    key_creator.create_keys()
                    self.temp_path = key_creator.temp_path
                else:
                    raise EncryptionError(
                        'Encryption keys not found. Not auto-creating. '
                        f'settings.DEBUG={settings.DEBUG}, '
                        f'settings.AUTO_CREATE_KEYS={self.auto_create_keys}. '
                        f'For a production system, generate the production '
                        f'encryption keys using the management command.')
            else:
                sys.stdout.write(
                    f' * found encryption keys in {key_files.key_path}.\n')
            self._keys = Keys(use_temp_path=self.is_temp_command)
            self._keys.load_keys()
            sys.stdout.write(
                f' * using model {self.app_label}.crypt.\n')
            sys.stdout.write(f' Done loading {self.verbose_name}.\n')
            sys.stdout.flush()

    def ready(self):
        if not self.app_Loaded:
            cryptor = Cryptor()
            if cryptor.aes_encryption_mode == AES.MODE_CFB:
                sys.stdout.write(style.NOTICE(
                    'Warning: Encryption mode MODE_CFB should not be used. \n'
                    '         See django_crypto_fields.cryptor.py and comments \n'
                    '         in pycrypto.blockalgo.py.\n'))
                sys.stdout.flush()
            self.app_Loaded = True

    @property
    def encryption_keys(self):
        if not self._key_path_validated:
            try:
                self._key_path_validated = self.key_path_validated
            except (AppRegistryNotReady, TypeError):
                pass
        return self._keys

    @property
    def key_path_validated(self):
        sys.stdout.write('Validating path for encryption keys ...\r')
        if not self.is_temp_command:
            model_cls = django_apps.get_model(self.key_reference_model)
            key_path = self._keys.key_path
            try:
                obj = model_cls.objects.all()[0]
            except IndexError:
                model_cls.objects.create(key_path=key_path)
            else:
                if obj.key_path != key_path:
                    sys.stdout.write(
                        f'Validating path for encryption keys ... {style.ERROR("ERROR")}\n')
                    raise DjangoCryptoFieldsKeyPathChangeError(style.ERROR(
                        f'Key path changed since last startup! '
                        f'Key path has been unexpectedly changed from '
                        f'\'{obj.key_path}\'  to \'{key_path}\'. You must resolve '
                        f'this before using the system. See {self.key_reference_model} '
                        f'and settings.KEY_PATH'))
            sys.stdout.write(
                f'Validating path for encryption keys ... {style.SUCCESS("OK")}\n')
        else:
            sys.stdout.write(
                f'Validating path for encryption keys ... {style.WARNING("SKIPPING")}\n')
        return True
