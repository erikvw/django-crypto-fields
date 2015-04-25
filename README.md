# crypto_fields
model field-level encryption used in our Edc project (Django)


This module is used in our Edc projects to handle field level encryption for sensitive field values such as names, identifiers, dob, etc (PII). Users accessing the data through the Edc can see PII. Users accessing the DB directly cannot.

This module depends on M2Crypto which currently does not offer support for python3. 

We plan to rewrite using a different encryption module such as http://cryptography.io that supports python3. Also, it needs to be cleaned up a bit anyway.

This module is intended to be used as an app in a Django project.

