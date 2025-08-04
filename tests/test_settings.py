import sys
from pathlib import Path

from edc_test_settings.default_test_settings import DefaultTestSettings

app_name = "django_crypto_fields"
base_dir = Path(__file__).absolute().parent.parent

project_settings = DefaultTestSettings(
    calling_file=__file__,
    BASE_DIR=base_dir,
    APP_NAME=app_name,
    DJANGO_CRYPTO_FIELDS_KEY_PATH=base_dir / "tests" / "crypto_keys",
    GIT_DIR=base_dir.parent.parent,
    DJANGO_REVISION_IGNORE_WORKING_DIR=True,
    INSTALLED_APPS=[
        "django.contrib.admin",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.messages",
        "django.contrib.sessions",
        "django.contrib.sites",
        "django.contrib.staticfiles",
        "django_revision.apps.AppConfig",
        f"{app_name}.apps.AppConfig",
    ],
).settings

for k, v in project_settings.items():
    setattr(sys.modules[__name__], k, v)
