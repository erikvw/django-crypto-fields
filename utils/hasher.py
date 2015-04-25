#!/usr/bin/python
"""A command line hasher that hashes value according to the Edc
crypto_fields hash algorithm.

If using the same salt, hasher will return the same value as the
Edc in the model field to link to the secret. hasher returns a
salted hash after iterating on the digest.

Args:
    value = any ascii value

Usage: python hasher.py <value>
"""

import hashlib
import sys

from salt import rsa_restricted_salt

SALT = rsa_restricted_salt
HASH_PREFIX = 'enc1:::'
ITERATIONS = 39


def hasher():
    '''Entry point if called as an executable'''
    try:
        expected_hash = sys.argv[2]
        print 'hashing ' + sys.argv[1]
    except IndexError:
        expected_hash = None
    my_digest = hashlib.sha256('{0}{1}'.format(
        SALT, sys.argv[1]).decode('ascii', 'ignore')).digest()
    for _ in range(0, ITERATIONS):
        my_digest = hashlib.sha256(my_digest.decode('ascii', 'ignore')).digest()
    hashed_value = '{}{}'.format(HASH_PREFIX, my_digest.encode("hex"))
    confirmed = ''
    if expected_hash:
        confirmed = '  OK' if hashed_value == sys.argv[2] else 'Error'
    return '{}{}'.format(hashed_value, confirmed)

if __name__ == '__main__':
    print hasher()
