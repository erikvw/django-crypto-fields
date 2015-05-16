Examples
========

Review your consent models, locator models and any other models that store personally identifying information. 
Replace the current field class with a :mod:`bhp_crypto`  field class.

National Identity Number
------------------------

For example, on a consent form the national identity number is documented in the field *identity*. :mod:`bhp_crypto` 
provides a field class for *identity* which is a subclass of :class:`RestrictedRsaEncryptionField` and, as the 
class name suggests, employs RSA encryption using the **restricted-rsa** key pair. A :class:`RestrictedRsaEncryptionField` 
does not require the private key to be available to the EDC for normal operation. This is a good choice for the 
*identity number* as once the *identity number* is captured there is usually no reason to decrypted it. 

.. code-block:: python
    
    from django.db.models import CharField

    class ConsentModel(BaseModel):
        ...
    
        identity = CharField(
            max_length=35,
            null=True,
            blank=True,
            )

would become:
    
.. code-block:: python
    
    from edc.core.crypto_fields.fields import EncryptedIdentityField
    
    class ConsentModel(BaseModel):
    
        ...
    
        identity = EncryptedIdentityField(
            null=True,
            blank=True,
            ) 
            


               