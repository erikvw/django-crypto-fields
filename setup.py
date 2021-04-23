# -*- coding: utf-8 -*-
import os

from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), "README.rst")) as readme:
    README = readme.read()

with open(os.path.join(os.path.dirname(__file__), "VERSION")) as f:
    VERSION = f.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name="django-crypto-fields",
    version=VERSION,
    author="Erik van Widenfelt",
    author_email="ew2789@gmail.com",
    packages=find_packages(),
    include_package_data=True,
    url="http://github.com/erikvw/django-crypto-fields",
    license="GPL license, see LICENSE",
    description="Add encrypted field classes and more to your Django models.",
    long_description=README,
    zip_safe=False,
    keywords="django fields encryption security",
    install_requires=[
        "pycryptodome",
        "django_audit_fields",
        "edc-utils>=0.3.0",
        "edc-model-fields>=0.3.0",
        "django-extensions",
    ],
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.7",
)
