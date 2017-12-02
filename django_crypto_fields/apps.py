import sys

from django.apps import AppConfig as DjangoAppConfig
from django.conf import settings
from django.core.management.color import color_style
from django.core.checks import register

from .system_checks import key_path_check, aes_mode_check, encryption_keys_check
from .key_creator import KeyCreator
from .key_files import KeyFiles
from .keys import Keys


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
    last_key_path_filename = 'django_crypto_fields'
    key_reference_model = 'django_crypto_fields.keyreference'
    # change if using more than one database and not 'default'.
    crypt_model_using = 'default'
    temp_path = None
    ignore_argv = ['test', 'makemigrations', 'migrate', 'check']

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
        sys.stdout.write(f'Loading {self.verbose_name} ...\n')
        super().__init__(app_label, model_name)
        key_files = KeyFiles()
        if not self._keys:
            if not key_files.key_files_exist:
                if self.auto_create_keys or sys.argv in self.ignore_argv:
                    sys.stdout.write(style.SUCCESS(
                        f' * settings.AUTO_CREATE_KEYS={self.auto_create_keys}.\n'))
                    key_creator = KeyCreator(
                        use_temp_path=self.is_temp_command)
                    key_creator.create_keys()
                    self.temp_path = key_creator.temp_path
                else:
                    sys.stdout.write(style.WARNING(
                        f' * settings.AUTO_CREATE_KEYS={self.auto_create_keys}.\n'))
            self._keys = Keys(use_temp_path=self.temp_path)
            self._keys.load_keys()

    def ready(self):
        register(key_path_check)(['django_crypto_fields'])
        register(encryption_keys_check)(
            ['django_crypto_fields'],
            auto_create_keys=self.auto_create_keys or sys.argv in self.ignore_argv)
        register(aes_mode_check)(['django_crypto_fields'])
        key_files = KeyFiles(use_temp_path=self.temp_path)
        sys.stdout.write(
            f' * found encryption keys in {key_files.key_path}.\n')
        sys.stdout.write(
            f' * using model {self.app_label}.crypt.\n')
        sys.stdout.write(f' Done loading {self.verbose_name}.\n')

    @property
    def encryption_keys(self):
        return self._keys
