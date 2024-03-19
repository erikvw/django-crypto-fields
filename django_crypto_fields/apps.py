import os
import sys

from django.apps import AppConfig as DjangoAppConfig
from django.core.management.color import color_style

from .key_path import KeyPath


class AppConfig(DjangoAppConfig):
    name: str = "django_crypto_fields"
    verbose_name: str = "django-crypto-fields"
    app_label: str = "django_crypto_fields"
    crypt_model_using: str = "default"

    def import_models(self):
        from .keys import encryption_keys  # noqa

        return super().import_models()

    def ready(self):
        style = color_style()
        path = KeyPath().path
        sys.stdout.write(f"Loading {self.verbose_name} ...\n")
        sys.stdout.write(f" * Keys are in folder {path}\n")
        if os.access(path, os.W_OK):
            sys.stdout.write(
                style.WARNING(" * Remember to make folder READ-ONLY in production\n")
            )
        sys.stdout.write(
            style.WARNING(" * Remember to keep a backup of your encryption keys\n")
        )
        sys.stdout.write(f" Done loading {self.verbose_name}.\n")
