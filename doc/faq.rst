FAQ
===

Where is the RSA or AES secret stored?
--------------------------------------

Only the hash of the value is stored in the model field while the *secret* is stored in a lookup table along with the hash. When
the value is needed, the field class retrieves the *secret* by searching the lookup table on the hash.

Is it still possible to search on encrypted fields?
---------------------------------------------------
Yes, but only exact matches are possible as the search is on the hash of the value and not the value itself. 

To search on RSA fields, the public keys are needed. 

To search on AES fields the ''local-rsa'' private key and the AES key are required.

Note that hashing is used because the cipher object does not create the same *secret* each time it ciphers a given value. 