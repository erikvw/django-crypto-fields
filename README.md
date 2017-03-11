[![Build Status](https://travis-ci.org/erikvw/django-crypto-fields.svg?branch=master)](https://travis-ci.org/erikvw/django-crypto-fields)
[![Coverage Status](https://coveralls.io/repos/erikvw/django-crypto-fields/badge.svg)](https://coveralls.io/r/erikvw/django-crypto-fields)

django-crypto-fields
=====================

Add encrypted field classes to your Django models where `unique=True` and `unique_together` attributes work as expected.

For example:

	from django.db import models
	from django_crypto_fields.fields import EncryptedTextField, FirstnameField, IdentityField

	class PatientModel (models.Model):

	    first_name = FirstnameField(
	        verbose_name="First Name")

	    identity = IdentityField(
	        verbose_name="Identity",
	        unique=True)

	    comment = EncryptedTextField(
	        max_length=500)

Installation
------------

    pip install git+https://github.com/erikvw/django-crypto-fields@develop#egg=django-crypto-fields

Macosx installation issue with `pycrypto`. `django-crypto-fields` requires `pycrypto`. If `pycrypto` has trouble installing try:

    CFLAGS="-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk -I/usr/local/include" LDFLAGS="-L/usr/local/lib" pip install pycrypto

On Ubuntu first install:
    
    sudo apt-get install build-essential libssl-dev libffi-dev python-dev

Once installed, add to INSTALLED_APPS:

	INSTALLED_APPS = (
		...
	    'django_crypto_fields.apps.AppConfig',
	    ...
	)

Add KEY_PATH to the folder in settings:

    # folder where the encryption keys are stored
    KEY_PATH = '/Volumes/secure_drive/keys')

Add KEY_PREFIX (optional, the default is "_user_"):

	# optional filename prefix for encryption keys files:
	KEY_PREFIX = 'bhp066'

Run _migrate_ to create the _crypto_fields_crypt_ table:

    python manage.py migrate django_crypto_fields

Generate encryption keys:

    python manage.py generate_keys


Using a custom `Crypt` model
----------------------------

To use a custom `Crypt` model, as is required if the `Crypt` model is used in data synchronization, declare a tuple to reference the model on the `AppConfig`. If you have an app `myapp` then you `apps.py` might look like this:

    from django.apps import AppConfig as DjangoAppConfig
    from django_crypto_fields.apps import AppConfig as DjangoCryptoFieldsAppConfigParent
    
    class AppConfig(DjangoAppConfig):
        name = 'my_app'

    class DjangoCryptoFieldsAppConfig(DjangoCryptoFieldsAppConfigParent):
        model = ('example', 'crypt')
    
    
And then change settings INSTALLED_APPS:

    INSTALLED_APPS = (
        ...
        'myapp.apps.DjangoCryptoFieldsAppConfig',
        'myapp.apps.AppConfig',
    )
        
See also module `edc-sync`.

Legacy Mode
-----------

As of version 0.1.7, the default AES encryption mode is CBC. To run in legacy mode (CFB) add to `settings.py`:

    AES_ENCRYPTION_MODE = AES.MODE_CFB


History
-------

_django-crypto-fields_ has been used in our audited research projects that use our "Edc" for data collection and management. Data collected in our Edc are considered "source documents". _django-crypto-fields_ adds field level encryption for sensitive field values such as names, identifiers, dob, etc (PII). Authorized study personnel accessing the data through the application can see PII. Downstream data management staff and statisticians accessing the database directly cannot.

Features
--------

- All values are stored as a pair of hash (hashlib.pbkdf2_hmac) and secret (rsa or aes);
- A model using a _django-crypto-fields_ field class stores the hash only;
- A separate table relates the hash to it's secret and is referenced internally by the field class;

Advantages
----------

- Automatically creates encryption key sets (RSA, AES and salt) and stores them in the KEY_PATH folder;
- Supports unique constraints and compound constraints that including encrypted fields. The hash is stored in the model's db_table and not the secret. The __unique=True__ and __unique_together__ attributes work as expected;
- The dataset is de-identified at rest. This has many advantages but helps us work well with our analysis team. The data analysis team do not need to see PII. They just want a de-identified dataset. A de-identified dataset is one where PII fields are encrypted and others not. With the RSA keys removed, the dataset is effectively de-identified;
- Datasets from other systems with shared PII values, such as identity numbers, can be prepared for meta-analysis using the same keys and algorithms;
- The dataset can be permanently obscured by dropping the Crypt table from the DB (it has all the secrets);
- By default field classes exist for two sets of keys. You can customize KEY_FILENAMES to create as many sets as needed. With multiple sets of keys you have more control over who gets to see what.

Disadvantages
-------------

- Limited support for lookup types. The "query value" is the hash not the decrypted secret, so Django lookups like ['startswith', 'istartswith', 'endswith', 'iendswith', 'contains', 'icontains', 'iexact'] are not supported.
- Hashing with a secret may be considered less secure than just a "secret". You decide what your requirements are. For systems that collect PII in fields classes from _django-crypto-fields_, we take all the basic security precautions: OS and application-level password protection, Full-Drive encryption, physical security and so on.  

Other encrypted field modules are available if you just want to use encrypted field classes in Django models and do not need unique constraints nor plan to join tables on encrypted fields for analysis.

Contribute
----------

- Issue Tracker: github.com/erikvw/django-crypto-fields/issues
- Source Code: github.com/erikvw/django-crypto-fields

License
-------

The project is licensed under the GPL license.
