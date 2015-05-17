[![Build Status](https://travis-ci.org/erikvw/django-crypto-fields.svg?branch=master)](https://travis-ci.org/erikvw/django-crypto-fields)
[![Coverage Status](https://coveralls.io/repos/erikvw/django-crypto-fields/badge.svg)](https://coveralls.io/r/erikvw/django-crypto-fields)
[![Documentation Status](https://readthedocs.org/projects/crypto-fields/badge/?version=latest)](https://readthedocs.org/projects/crypto-fields/?badge=latest)

django-crypto-fields
=====================

Add encrypted fields classes to your Django models.

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

- unique constraint on encrypted fields: because the hash is stored in the model's db_table and not the secret, the unique=True parameter works as well as the django.form validation messages.    
- de-identified dataset: the data analysis team should never need to see PII. They just want a de-identified dataset. A de-identified dataset is one where PII fields are encrypted and others not. With the RSA key removed, the dataset is effectively deidentified.
- datasets from other systems with shared values, such as identity numbers, can be prepared for meta-analysis using the same keys and algorithms;
- To completely obscure the encrypted data, the secret reference table may be dropped before releasing the database.

Disadvantages
-------------

- Hashing with a secret may be considered less secure than just a "secret". You decide what your requirements are. For systems that collect PII in fields classes from _django-crypto-fields_, we take all the basic security precautions: OS and application-level password protection, Full-Drive encryption, physical security and so on.  

Other encrypted field modules are available if you just want to use encrypted field classes in Django models and do not need unique constraints nor plan to join tables on encrypted fields for analysis.


Contribute
----------

- Issue Tracker: github.com/erikvw/django-crypto-fields/issues
- Source Code: github.com/erikvw/django-crypto-fields

License
-------

The project is licensed under the GPL license.
