Before You Begin
================

Once :mod:`bhp_crypto` is installed, review the models in your applications to identify fields that should use encryption.
A data model is well designed if all the personally identifying information (PII) is kept in a just a few models. In the 
EDC, PII is found in model `registered_subject`, the locator models and the consent models.

.. warning:: Thoroughly test before implementing :mod:`bhp_crypto` in production or with real data.

.. warning:: Have a secure backup of encryption keys. Without the keys, data is lost.         
        