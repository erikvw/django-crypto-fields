import sys

from django.apps import AppConfig

from django.core.management.color import color_style


class DjangoCryptoFieldsError(Exception):
    pass


class DjangoCryptoFieldsAppConfig(AppConfig):
    name = 'django_crypto_fields'
    verbose_name = "Data Encryption"
    encryption_keys = None
    model = ('django_crypto_fields', 'crypt')
    crypt_model_using = 'default'  # change if using more than one database and not 'default'.

    def __init__(self, app_label, model_name):
        """Placed here instead of `ready()`. For models to load correctly that use
        field classes from this module the keys need to be loaded before models."""
        super(DjangoCryptoFieldsAppConfig, self).__init__(app_label, model_name)
        from django_crypto_fields.keys import Keys
        keys = Keys()
        if not self.encryption_keys:
            style = color_style()
            sys.stdout.write('Loading {} ...\n'.format(self.verbose_name))
            if not keys.key_files_exist():
                sys.stdout.write(style.NOTICE('Warning: {} failed to load encryption keys.\n'.format(
                    self.verbose_name)))
                sys.stdout.write('Confirm that settings.KEY_PATH points to the correct folder.\n')
                sys.stdout.write('Loading the wrong encryption keys can corrupt sensitive data.\n')
                sys.stdout.write('If this is your first time loading the project, '
                                 'new keys will be generated\n')
                sys.stdout.write('and placed in the settings.KEY_PATH folder.\n')
                keys.create_keys()
            keys.load_keys()
            self.encryption_keys = keys


class TestDjangoCryptoFieldsApp(DjangoCryptoFieldsAppConfig):
    name = 'django_crypto_fields'
    model = ('example', 'crypt')
