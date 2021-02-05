import os
import sys
from tempfile import mkdtemp

from django.apps import AppConfig as DjangoAppConfig
from django.conf import settings
from django.core.checks import register
from django.core.management.color import color_style

from .key_creator import KeyCreator
from .key_files import KeyFiles
from .key_path import KeyPath
from .keys import Keys
from .persist_key_path import get_last_key_path
from .system_checks import aes_mode_check, encryption_keys_check, key_path_check


class DjangoCryptoFieldsError(Exception):
    pass


class DjangoCryptoFieldsKeysDoNotExist(Exception):
    pass


style = color_style()


class AppConfig(DjangoAppConfig):
    name = "django_crypto_fields"
    verbose_name = "Data Encryption"
    _keys = None
    _key_path_validated = None
    app_label = "django_crypto_fields"
    last_key_path_filename = "django_crypto_fields"
    key_reference_model = "django_crypto_fields.keyreference"
    # change if using more than one database and not 'default'.
    crypt_model_using = "default"

    def __init__(self, app_label, model_name):
        """Placed here instead of `ready()`. For models to
        load correctly that use field classes from this module the keys
        need to be loaded before models.
        """
        self.temp_path = mkdtemp()

        path = None
        DJANGO_CRYPTO_FIELDS_TEMP_PATH = getattr(
            settings, "DJANGO_CRYPTO_FIELDS_TEMP_PATH", "test" in sys.argv
        )
        if DJANGO_CRYPTO_FIELDS_TEMP_PATH:
            path = self.temp_path

        self._key_path = KeyPath(path=path)
        self.key_files = None
        self.last_key_path = get_last_key_path(self.last_key_path_filename)

        sys.stdout.write(f"Loading {self.verbose_name} (init)...\n")

        self.key_files = KeyFiles(key_path=self.key_path)
        if not self._keys and not self.key_files.key_files_exist:
            if self.auto_create_keys:
                if not os.access(self.key_path.path, os.W_OK):
                    raise DjangoCryptoFieldsError(
                        "Cannot auto-create encryption keys. Folder is not writeable."
                        f"Got {self.key_path}"
                    )
                sys.stdout.write(
                    style.SUCCESS(
                        f" * settings.AUTO_CREATE_KEYS={self.auto_create_keys}.\n"
                    )
                )
                key_creator = KeyCreator(key_files=self.key_files, verbose_mode=True)
                key_creator.create_keys()
                self._keys = Keys(key_path=self.key_path)
                self._keys.load_keys()
            else:
                raise DjangoCryptoFieldsKeysDoNotExist(
                    f"Failed to find any encryption keys in path {self.key_path}. "
                    "If this is your first time loading "
                    "the project, set settings.AUTO_CREATE_KEYS=True and restart. "
                    "Make sure the folder is writeable."
                )

                sys.stdout.write(
                    style.WARNING(
                        f" * settings.AUTO_CREATE_KEYS={self.auto_create_keys}.\n"
                    )
                )
        else:
            self._keys = Keys(key_path=self.key_path)
            self._keys.load_keys()

        super().__init__(app_label, model_name)
        sys.stdout.write(f" Done loading {self.verbose_name} (init)...\n")

    def ready(self):
        sys.stdout.write(f"Loading {self.verbose_name} ...\n")
        if "test" not in sys.argv:
            register(key_path_check)(["django_crypto_fields"])
        register(encryption_keys_check)(["django_crypto_fields"])
        register(aes_mode_check)
        sys.stdout.write(f" * found encryption keys in {self.key_path}.\n")
        sys.stdout.write(f" * using model {self.app_label}.crypt.\n")
        sys.stdout.write(f" Done loading {self.verbose_name}.\n")

    @property
    def encryption_keys(self):
        return self._keys

    @property
    def auto_create_keys(self):
        try:
            auto_create_keys = settings.AUTO_CREATE_KEYS
        except AttributeError:
            auto_create_keys = None
        if "test" in sys.argv:
            if auto_create_keys is None:
                auto_create_keys = True
        return auto_create_keys

    @property
    def key_path(self):
        return self._key_path
