Installation
============

.. warning:: Try :mod:`bhp_crypto` in a test environment first. 

Copy your existing project and dataset into your test environment.

Checkout the latest version of :mod:`bhp_crypto` into your test environment project folder::

    svn co http://192.168.1.50/svn/bhp_crypto

Checkout two additional modules::

    svn co http://192.168.1.50/svn/bhp_base_model
    svn co http://192.168.1.50/svn/bhp_common


Add :mod:`bhp_crypto` to your project ''settings'' file::

    INSTALLED_APPS = (
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.sites',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'django.contrib.admin',
        'django.contrib.admindocs',
        'django_extensions',
        'audit_trail',
        'bhp_base_model',
        'bhp_common',
        'bhp_crypto',
        ...
        )
      

Add these attributes to the bottom of your project ''settings'' file::

    # bhp_crypto settings
    KEY_PATH='/Volume/protected_keys/keys' # truecrypt volume recommended!
    IS_SECURE_DEVICE=False

Protect the keys! Point **KEY_PATH** to a folder on a :doc:`truecrypt</protecting_keys_with_truecrypt>` drive.

Generate new encryption keys::

    python manage.py shell_plus
    
    >>>from edc.core.crypto_fields.utils import setup_new_keys()
    >>>setup_new_keys()
    >>>exit()
    
Check that your keys were created and BACK THEM UP immediately::

    ls keys/
    
    erikvw@mac:~/source/bhp056_project/bhp056$  ls keys
    user-aes-local              
    user-encrypted-salt         
    user-public-irreversible.pem
    user-public-restricted.pem
    user-private-restricted.pem
    user-public-local.pem
    user-private-local.pem      
    
Your keys should be protected when in rest. See :doc:`protecting_keys_with_truecrypt`. 


    
        