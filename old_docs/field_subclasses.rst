Field SubClasses for Models
---------------------------               

RSA Encryption
++++++++++++++
RSA encryption supports short text fields. In :mod: 'bhp_crypto' it is deployed at three levels of security:

1. Irreversible RSA: private key does not exist.
2. Restricted RSA: private key exists but is often not available to the device running the application.
3. Local RSA: private key is usually available to the device running the application

In all cases, all private keys may be removed to disable the rsa_decrypt() method.

**Resrticted RSA**

.. autoclass:: bhp_crypto.fields.EncryptedLastnameField
    :members:    
    :show-inheritance:

.. autoclass:: bhp_crypto.fields.EncryptedIdentityField
    :members:    
    :show-inheritance:

**Local RSA**

.. autoclass:: bhp_crypto.fields.EncryptedFirstnameField
    :members:    
    :show-inheritance:

.. autoclass:: bhp_crypto.fields.EncryptedCharField
    :members:    
    :show-inheritance:

.. autoclass:: bhp_crypto.fields.EncryptedIntegerField
    :members:    
    :show-inheritance: 
       
.. autoclass:: bhp_crypto.fields.EncryptedDecimalField
    :members:    
    :show-inheritance:    
    
AES Encryption
++++++++++++++
AES Encryption supports long text field. The keys, though protected, are on the device running the application.

.. autoclass:: bhp_crypto.fields.EncryptedAesCharField
    :members:    
    :show-inheritance:
    
.. autoclass:: bhp_crypto.fields.EncryptedTextField
    :members:    
    :show-inheritance:
    
.. autoclass:: bhp_crypto.fields.EncryptedOtherCharField
    :members:    
    :show-inheritance:        

.. automodule:: bhp_crypto.utils
    :members:
    