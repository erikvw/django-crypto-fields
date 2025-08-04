Key management
==============

Securely managing encryption keys is critical. Implement proper key management practices, including safe storage and access control mechanisms, to ensure data security

Encryption keys
---------------

Take care of the encryption keys!

In your tests you can set ``settings.DEBUG = True`` and ``settings.AUTO_CREATE_KEYS = True`` so that keys are generated for your tests. Encryption keys will not automatically generate on a production system (``DEBUG=False``) unless ``settings.AUTO_CREATE_KEYS = True``.

By default assumes your test module is ``runtests.py``. You can changes this by setting ``settings.DJANGO_CRYPTO_FIELDS_TEST_MODULE``.

When are encryption keys loaded?
--------------------------------

The encryption keys are loaded as a side effect of accessing the ``keys`` module.
The keys module is imported in this apps AppConfig just before ``import_models``.
During runtime the encryption keys are stored in the ``encryption_keys`` global.

See module ``apps.py``, module ``keys.py`` and ``fields.BaseField`` constructor.
