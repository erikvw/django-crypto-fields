Choosing a Field Class for Your Model
=====================================

Field classes in :mod:`bhp_crypto` are designed to protect sensitive data stored in models. In a clinical trail setting, any 
model field that contains **personally identifying information** (PII) must use encryption. Some examples of PII include a 
subject's first and last name, identity number, cell number, address, directions to a residence, names of relatives and date of birth. 

''bhp_crypto'' offers field classes that use either RSA and AES encryption. RSA is used for short text and AES for long text. 

If :mod:`bhp_crypto` does not have the required keys to encrypt a field value, an error will be raised on any attempt to save data.

All data additions and changes will raise an error if the restricted and local RSA private keys are unavailable to the application.


RSA Encryption
--------------
There are three types of RSA field classes where the difference is determined by the existence or availability of the private RSA key:

    1. **Irreversible RSA**: the saved value is never to be decrypted. Uses only a public RSA key:
        * public key *user-public-irreversible.pem* 
        * private key *does not exist!* 
    2. **Restricted RSA**: private key and normally NOT stored on the device running the application. Uses RSA keys: 
        * public key *user-public-restricted.pem*
        * private key *user-private-restricted.pem* .
    3. **Local RSA**: private key is usually available to the device running the application. Uses RSA keys: 
        * public key *user-public-local.pem*
        * private key *user-private-local.pem*

Usage
+++++
Irreversible RSA can be used to collect information meant to remain anonymous. For example, collecting samples at
multiple time points form a subject whose identity must remain anonymous but needs to be confirmed and linked in data.
By using Irreversible RSA, the field class creates a hash and secret of the PII but no private key exists
to reverse the encryption. 

Restricted RSA is useful for the subject's identity number and lastname. Under normal operation, the private key is 
not available to the application and these values are cannot be decrypted during normal use.

Local RSA is used for PII that unfortunately is needed for normal operation of the EDC. This includes values such as
*first name, initials, date of birth, cell number, relative's name, and any other moderately sensitive value**. 


AES Encryption
--------------    
AES encryption uses a secret AES key stored in *user-aes-local*. The key is stored as an RSA secret created with the LocalRSA cipher. 
This means that the local-rsa private key must be available for AES encryption. Uses keys:
    
    * aes key *user-aes-local*
    * private key *user-private-local.pem* (required to decrypt the aes key)

Note that AES and Local RSA are linked by the same private key. The reason for this is that the level of security required 
for data saved using either method is expected to be the same. 

By removing the *local-rsa* private key, an attempt to save a field value through a field class using AES will raise an error.   
    
Usage
+++++

Use AES encryption for an field that is a long text and may contain sensitive information. A locator form with
*directions to a household* or a *comment* field on a consent document are good examples.     
      

Application, Data and Keys
--------------------------      
    * A dataset with encrypted PII is only de-identified by removing BOTH the restricted and local RSA private keys from the application. 
    * the AES key is not available if the local RSA private key is not available
    * AES encryption is not possible if the AES key is not available
    * If a field class cannot encrypt a value, an error will be raised.
      


