Overview
========   

Module :mod:`bhp_crypto` provides django model field classes that encrypt. 

    1. Depending on the length of the text field required, either RSA or AES encryption is used. 
    2. Not all field classes use the same encryption keys, so field value types can be 
       grouped by the key pair used and user access to un-encrypted values can be managed 
       according to these groupings.  
    3. Unique field constraints are maintained through the combined use of hashing and
       ciphering values.  
    4. Only the hashed and ciphered value are stored.
    5. Search is possible but only for exact value matches. 
    
.. note:: Field level encryption protects data at rest but by itself is not 
    sufficient to protect a system. Any project that uses :mod:`bhp_crypto` 
    should be deployed on a system that uses full-drive encryption and the 
    best of BIOS and OS level security features.  