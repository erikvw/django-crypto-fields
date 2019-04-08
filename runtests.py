#!/usr/bin/env python
import django
import logging
import os
import sys

from django.conf import settings
from django.test.runner import DiscoverRunner
from edc_test_utils import DefaultTestSettings
from os.path import abspath, dirname


app_name = 'django_crypto_fields'
base_dir = dirname(abspath(__file__))

DEFAULT_SETTINGS = DefaultTestSettings(
    calling_file=__file__,
    BASE_DIR=base_dir,
    APP_NAME=app_name,
    ETC_DIR=os.path.join(base_dir, app_name, "tests", "etc"),
    INSTALLED_APPS=[
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.messages',
        'django.contrib.sessions',
        'django.contrib.sites',
        'django.contrib.staticfiles',
        'django_revision.apps.AppConfig',
        'edc_device.apps.AppConfig',
        f'{app_name}.apps.AppConfig',
    ],
).settings


def main():
    if not settings.configured:
        settings.configure(**DEFAULT_SETTINGS)
    django.setup()
    failures = DiscoverRunner(failfast=False).run_tests(
        [f'{app_name}.tests'])
    sys.exit(failures)


if __name__ == "__main__":
    logging.basicConfig()
    main()
