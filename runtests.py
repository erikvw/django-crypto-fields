#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys

if __name__ == "__main__":
    os.environ["DJANGO_SETTINGS_MODULE"] = "django_crypto_fields.tests.test_settings"
    import django

    django.setup()
    from django.test.runner import DiscoverRunner

    tags = [t.split("=")[1] for t in sys.argv if t.startswith("--tag")]
    failfast = any([True for t in sys.argv if t.startswith("--failfast")])
    keepdb = any([True for t in sys.argv if t.startswith("--keepdb")])
    opts = dict(failfast=failfast, tags=tags, keepdb=keepdb)
    failures = DiscoverRunner(**opts).run_tests(["django_crypto_fields.tests"], **opts)
    sys.exit(failures)
