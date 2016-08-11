from django.apps import AppConfig as DjangoAppConfig
from django_crypto_fields.apps import AppConfig as DjangoCryptoFieldsAppConfigParent


class AppConfig(DjangoAppConfig):
    name = 'example'


class DjangoCryptoFieldsAppConfig(DjangoCryptoFieldsAppConfigParent):
    model = ('example', 'crypt')
