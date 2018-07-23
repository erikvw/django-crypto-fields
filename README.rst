|pypi| |travis| |coverage|

django-crypto-fields
--------------------

Add encrypted field classes to your Django models where ``unique=True`` and ``unique_together`` attributes work as expected.

For example:

.. code-block:: python


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

.. important:: this module has known problems with `postgres`.

Installation
============

add to INSTALLED_APPS:

.. code-block:: python

	INSTALLED_APPS = (
		...
	    'django_crypto_fields.apps.AppConfig',
	    ...
	)

Add KEY_PATH to the folder in settings:

.. code-block:: python

    # folder where the encryption keys are stored
    # Do not set for tests
    KEY_PATH = '/etc/myproject/django_crypto_fields')

Add KEY_PREFIX (optional, the default is "_user_"):

.. code-block:: python

	# optional filename prefix for encryption keys files:
	KEY_PREFIX = 'bhp066'

Run _migrate_ to create the _crypto_fields_crypt_ table:

.. code-block:: python

    python manage.py migrate django_crypto_fields


Encryption keys
===============

Take care of the encryption keys!

In your tests you can set `settings.DEBUG = True` and `settings.AUTO_CREATE_KEYS = True` so that keys are generated for your tests. Encryption keys to will not automatically generate on a production system (`DEBUG=False`). See `AppConfig.auto_create_keys`.

History
=======

``django-crypto-fields`` has been used in our audited research projects that use our "Edc" for data collection and management. Data collected in our Edc are considered "source documents". _django-crypto-fields_ adds field level encryption for sensitive field values such as names, identifiers, dob, etc (PII). Authorized study personnel accessing the data through the application can see PII. Downstream data management staff and statisticians accessing the database directly cannot.

Features
========

* All values are stored as a pair of hash (hashlib.pbkdf2_hmac) and secret (rsa or aes);
* A model using a ``django-crypto-fields`` field class stores the hash only;
* A separate table relates the hash to it's secret and is referenced internally by the field class;

Advantages
==========

- Automatically creates encryption key sets (RSA, AES and salt) and stores them in the ``KEY_PATH`` folder;
- Supports unique constraints and compound constraints that including encrypted fields. The hash is stored in the model's db_table and not the secret. The ``unique=True`` and ``unique_together`` attributes work as expected;
- The dataset is de-identified at rest. This has many advantages but helps us work well with our analysis team. The data analysis team do not need to see PII. They just want a de-identified dataset. A de-identified dataset is one where PII fields are encrypted and others not. With the RSA keys removed, the dataset is effectively de-identified;
- Datasets from other systems with shared PII values, such as identity numbers, can be prepared for meta-analysis using the same keys and algorithms;
- The dataset can be permanently obscured by dropping the Crypt table from the DB (it has all the secrets);
- By default field classes exist for two sets of keys. You can customize ``KEY_FILENAMES`` to create as many sets as needed. With multiple sets of keys you have more control over who gets to see what.

Disadvantages
=============

- Limited support for lookup types. The "query value" is the hash not the decrypted secret, so Django lookups like ``['startswith', 'istartswith', 'endswith', 'iendswith', 'contains', 'icontains', 'iexact']`` are not supported.
- Hashing with a secret may be considered less secure than just a "secret". You decide what your requirements are. For systems that collect PII in fields classes from ``django-crypto-fields``, we take all the basic security precautions: OS and application-level password protection, Full-Drive encryption, physical security and so on.  

Other encrypted field modules are available if you just want to use encrypted field classes in Django models and do not need unique constraints nor plan to join tables on encrypted fields for analysis.

Contribute
==========

- Issue Tracker: github.com/erikvw/django-crypto-fields/issues
- Source Code: github.com/erikvw/django-crypto-fields


.. |pypi| image:: https://img.shields.io/pypi/v/django-crypto-fields.svg
    :target: https://pypi.python.org/pypi/django-crypto-fields
    
.. |travis| image:: https://travis-ci.org/erikvw/django-crypto-fields.svg?branch=develop
    :target: https://travis-ci.org/erikvw/django-crypto-fields
    
.. |coverage| image:: https://coveralls.io/repos/github/erikvw/django-crypto-fields/badge.svg?branch=develop
    :target: https://coveralls.io/github/erikvw/django-crypto-fields?branch=develop
