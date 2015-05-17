[![Build Status](https://travis-ci.org/erikvw/django-crypto-fields.svg?branch=master)](https://travis-ci.org/erikvw/django-crypto-fields)
[![Coverage Status](https://coveralls.io/repos/erikvw/django-crypto-fields/badge.svg)](https://coveralls.io/r/erikvw/django-crypto-fields)
[![Documentation Status](https://readthedocs.org/projects/django-crypto-fields/badge/?version=latest)](https://readthedocs.org/projects/django-crypto-fields/?badge=master)

$django-crypto-fields
=====================

Add encrypted fields classes to your Django models.

For example:

	from django.db import models
	from django_crypto_fields.fields import EncryptedTextField, FirstnameField, IdentityField

	class PatientModel (BaseModel):

	    first_name = FirstnameField(
	        verbose_name="First Name")
	
	    identity = IdentityField(
	        verbose_name="Identity",
	        unique=True)
	
	    comment = EncryptedTextField(
	        max_length=500)


History
-------

$project has been used in our audited research projects that use our "Edc" for data collection and management. Data collected in our Edc are considered "source documents". $project adds field level encryption for sensitive field values such as names, identifiers, dob, etc (PII). Users accessing the data through these models fields can see PII. Users accessing the DB directly cannot.

Features
--------

- All values are stored as a pair of hash (hashlib.pbkdf2_hmac) and secret (rsa or aes);
- A model using a $project field class stores the hash only;
- A separate table relates the hash to it's secret and is referenced internally by the field class;

Advantages
----------

- unique constraint on encrypted fields: because the hash is stored in the model's db_table and not the secret, the unique=True parameter works as well as the django.form validation messages.    
- de-identified dataset: the data analysis team want a de-identified dataset; that is, where PII fields are encrypted and others not. With the RSA key removed, the encrypted fields in the dataset cannot be decrypted.   
- Since the hash of a value is always the same and cannot be reversed, these field classes support unique constraints and all the django admin features work.
- To completely obscure the encrypted data, the secret reference table may be dropped before releasing the database.

Disadvantages
-------------

Hashing with a secret may be considered less secure than just a "secret". You decide what your requirements are. For systems that collect PII in fields classes from $project, we take all the basic security precautions: OS and application-level password protection, Full-Drive encryption, physical security and so on.  

Other encrypted field modules are available if you just want to use encrypted field classes in Django models and do not need unique constraints nor plan to join tables on encrypted fields for analysis.


Contribute
----------

- Issue Tracker: github.com/erikvw/$project/issues
- Source Code: github.com/erikvw/$project

License
-------

The project is licensed under the GPL license.