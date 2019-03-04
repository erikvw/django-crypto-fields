from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def get_crypt_model():
    """
    Return the Crypt model that is active in this project.
    """
    try:
        DJANGO_CRYPTO_FIELDS_MODEL = settings.DJANGO_CRYPTO_FIELDS_MODEL
    except AttributeError:
        DJANGO_CRYPTO_FIELDS_MODEL = "django_crypto_fields.crypt"

    try:
        return django_apps.get_model(DJANGO_CRYPTO_FIELDS_MODEL, require_ready=False)
    except ValueError:
        raise ImproperlyConfigured(
            "DJANGO_CRYPTO_FIELDS_MODEL must be of the form 'app_label.model_name'"
        )
    except LookupError:
        raise ImproperlyConfigured(
            f"DJANGO_CRYPTO_FIELDS_MODEL refers to model {DJANGO_CRYPTO_FIELDS_MODEL} "
            "that has not been installed"
        )
