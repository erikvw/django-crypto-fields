[![Build Status](https://travis-ci.org/erikvw/crypto_fields.svg?branch=develop](https://travis-ci.org/erikvw/crypto_fields)

# crypto_fields
model field-level encryption used in our Edc projects (Django)

The develop branch is where we are rewriting using pyCrypto.

This module has been used in our Edc projects to handle field level encryption for sensitive field values such as names, identifiers, dob, etc (PII). Users accessing the data through the Edc can see PII. Users accessing the DB directly cannot.

All values are stored as a pair of hash (hashlib.pbkdf2_hmac) and secret (rsa or aes). A separate table relates the hash to it's secret. Since the hash of a value is always the same and cannot be reversed, these field classes support unique constraints and all the django admin features work.

For analysis, the datatable only has the hashed field values and is considered de-identified at rest but is still useable if joined on a key field that uses the same hashing algorithm.

To completely obscure the encrypted data, the "crypt" table may be dropped before releasing the database. 

Other encrypted field modules are available if you just want to use encrypted field classes in Django models and do not need unique constraints nor plan to join tables on encrypted fields for analysis.

This module is intended to be used in a Django project.

