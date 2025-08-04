Considerations
==============

Is the approach right for your needs?
-------------------------------------
A hash of the secret is stored as the field value. The secret is stored in a seperate table referenced by the hash. Hashing with a secret may be considered less secure than just a "secret". You decide your requirements.

For systems that collect PII in fields classes from ``django-crypto-fields``, we take all the basic security precautions: OS and application-level password protection, Full-Drive encryption, physical security and so on.

Django lookup types
-------------------
Since only the hash is stored as the field value, ``django-crypto-fields`` has limited support for lookup types on the fields it encrypts. The "query value" is the hash not the decrypted secret, so Django lookups like ``['startswith', 'istartswith', 'endswith', 'iendswith', 'contains', 'icontains', 'iexact']`` are not supported.

Performance Overhead
--------------------
Encryption and decryption processes inherently add some overhead to application performance.
