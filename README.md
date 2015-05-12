# crypto_fields
model field-level encryption used in our Edc project (Django)


This module is used in our Edc projects to handle field level encryption for sensitive field values such as names, identifiers, dob, etc (PII). Users accessing the data through the Edc can see PII. Users accessing the DB directly cannot.

All values are stored as a pair of hash and secret. A separate table relates the hash to it's secret. The hash is created consistently for a given value. This approach means a unique constraint may be applied to an encrypted field and all the django admin features work. With the hash as a placeholder for the secret the database is useable for analysis and de-identified at rest. To completely obscure the encrypted data, the "crypt" table may be dropped before releasing the database. 

This module depends on M2Crypto which currently does not offer support for python3. 

The develop branch is where we are rewriting using pyCrypto. (Also, it needs to be cleaned up a anyway).

This module is intended to be used as an app in a Django project.

