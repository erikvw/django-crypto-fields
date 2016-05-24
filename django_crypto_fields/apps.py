from django.apps import AppConfig
from django_crypto_fields.classes.keys import Keys


class DjangoCryptoFieldsConfig(AppConfig):
    name = 'django_crypto_fields'
    verbose_name = "Data Encryption"
    encryption_keys = Keys()
