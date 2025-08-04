Overview
========

The Django-crypto-fields module is designed for applications handling sensitive data, like Personally Identifiable Information (PII) in clinical trials. It encrypts data at the field level, meaning specific sensitive fields in a Django model are encrypted, while other fields remain unencrypted.

Here's how it generally approaches data encryption:

Field-level Encryption
----------------------
It focuses on encrypting individual fields within a Django model that contain sensitive information like patient names, addresses, or medical records.

Hash and Secret Storage
-----------------------
It stores data as a combination of a hash and a secret. The model stores only the hash, while a separate table stores the hash and its corresponding secret.

Key Management
--------------
The module automatically generates encryption key sets (RSA, AES and salt) and stores them in a designated folder (KEY_PATH).

Access Control
--------------
This separation ensures that authorized personnel with application access can view the decrypted PII, while direct database access reveals only the encrypted data, protecting patient privacy.
Unique Constraints: It supports unique constraints and compound constraints, including encrypted fields, which might be helpful in maintaining data integrity while using encryption.
Benefits for clinical trials
PII Protection
--------------
Helps safeguard sensitive patient data from unauthorized access or breaches by encrypting it at the field level.
Compliance: Facilitates compliance with data privacy regulations such as HIPAA and GDPR by enhancing data protection in data collection systems.
Audit Trails
------------
The separation of hashes and secrets creates a clear trail of access and modifications, contributing to data accountability and compliance with regulatory requirements.
