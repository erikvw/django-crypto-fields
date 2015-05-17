Protecting Keys with Truecrypt
==============================

The EDC is designed to run on a secure server or an independent mobile device such as a netbook. 
In the latter case, securing the *encryption keys* is an important concern and storing the keys 
in a **truecrypt** encrypted mountable file is one approach.

.. tip:: See BHP's SOP on managing netbooks deployed in a disconnected environment

Download, install and create a **truecrypt** encrypted file::

   http://www.truecrypt.org/downloads

Point :mod:`bhp_crypto` to the **truecrypt** encrypted file by editing the KEY_PATH attribute in the project *settings* file. For example, 
if the **truecrypt** volume *project_keys* is mounted and the keys are in a sub-folder
named *keys*:

On macosx::

    KEY_PATH='/Volume/project_keys/keys'
    
On ubuntu::    

    KEY_PATH='/media/project_keys/keys'    