Overview
========

The ``django-crypto-fields`` module is designed for applications handling sensitive data, like Personally Identifiable Information (PII) in clinical trials. It encrypts data at the field level, meaning specific sensitive fields in a Django model are encrypted, while other fields remain unencrypted.

Here's how it generally approaches data encryption:

Field-level Encryption
----------------------
It focuses on encrypting individual fields within a Django model that contain sensitive information like patient names, addresses, or medical records.

Hash and Secret Storage
-----------------------
It stores data as a combination of a hash and a secret. The model stores only the hash, while a separate table stores the hash and its corresponding secret.

Key Management
--------------
``django-crypto-fields`` automatically generates encryption key sets (RSA, AES and salt) and stores them in a designated folder (KEY_PATH). By default field classes exist for two sets of keys. You can customize ``KEY_FILENAMES`` to create as many sets as needed. With multiple sets of keys you have more control over who gets to see what.

Access Control
--------------
The separation of hash and secret ensures that authorized personnel with application access can view the decrypted PII, while direct database access reveals only the hash pointer, protecting patient privacy. (See more detail below)

Unique Constraints
------------------
``django-crypto-fields`` supports unique constraints and compound constraints that including encrypted fields. The hash is stored in the model's db_table and not the secret. The ``unique=True`` and ``unique_together`` attributes work as expected

Benefits for clinical trials
----------------------------

PII Protection
++++++++++++++
Helps safeguard sensitive patient data from unauthorized access or breaches by encrypting it at the field level.
Compliance: Facilitates compliance with data privacy regulations such as HIPAA and GDPR by enhancing data protection in data collection systems.

Audit Trails
++++++++++++
The separation of hashes and secrets creates a clear trail of access and modifications, contributing to data accountability and compliance with regulatory requirements.

Data analysis workflow
++++++++++++++++++++++
The dataset is de-identified at rest. This has many advantages but helps you work well with your analysis team. The data analysis team do not need to see PII. They just want a de-identified dataset. A de-identified dataset is one where PII fields are encrypted and others not. With the RSA keys removed, the dataset is effectively de-identified;

* Datasets from other systems with shared PII values, such as identity numbers, can be prepared for meta-analysis using the same keys and algorithms;
* The dataset can be permanently obscured by dropping the ``Crypt`` table from the DB (it has all the secrets);
