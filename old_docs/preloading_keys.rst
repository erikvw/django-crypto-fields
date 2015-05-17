Pre-loading Keys
================

The encryption key *files* are not required once the EDC has loaded. All keys are
pre-loaded at start up. This would be once *runserver* or *apache* are up.

Since the keys are pre-loaded into memory at start-up, the encryption key *files* are not 
actually required after start-up and you may remove them as a security measure.

If the encryption key *files* are first read from a mounted truecrypt drive on the device,
it would be simple enough to unmount the drive once apache has started.

Even better, use sshfs to remotely mount the truecrypt drive, start apache, and unmount
the drive (or disconnect from the network).

This last option is ideal since you get all the functionality of :mod:`bhp_crypto` without 
storing the encryption key *files* on the device.
