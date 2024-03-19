from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path

from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA as RSA_PUBLIC_KEY
from Cryptodome.Util import number
from django.core.management.color import color_style

from ..constants import AES, PRIVATE, PUBLIC, RSA, RSA_KEY_SIZE, SALT
from ..exceptions import (
    DjangoCryptoFieldsError,
    DjangoCryptoFieldsKeyAlreadyExist,
    DjangoCryptoFieldsKeyError,
    DjangoCryptoFieldsKeysAlreadyLoaded,
    DjangoCryptoFieldsKeysDoNotExist,
)
from ..key_path import KeyPath, persist_key_path_or_raise
from ..utils import get_auto_create_keys_from_settings, get_key_prefix_from_settings
from .utils import get_filenames, get_template, key_files_exist, write_msg

style = color_style()


class Keys:
    """
    Class to prepare RSA, AES keys for use by field classes.

        * Keys are imported through the AppConfig __init__ method.
        * Keys are create through the AppConfig __init__ method, if necessary.
    """

    rsa_key_info: dict = {}
    key_prefix: str = get_key_prefix_from_settings()

    def __init__(self, verbose: bool = None):
        self.keys = None
        self.loaded = False
        self.verbose = True if verbose is None else verbose
        self.rsa_modes_supported = None
        self.aes_modes_supported = None
        self.path = KeyPath().path
        self.template = get_template(self.path, self.key_prefix)
        self.filenames = get_filenames(self.path, self.key_prefix)
        self.initialize()

    def initialize(self):
        """Load keys and create if necessary."""
        write_msg(self.verbose, "Loading encryption keys\n")
        self.keys = deepcopy(self.template)
        persist_key_path_or_raise()
        if not key_files_exist(self.path, self.key_prefix):
            self.create_new_keys_or_raise()
        self.load_keys()
        self.rsa_modes_supported = sorted([k for k in self.keys[RSA]])
        self.aes_modes_supported = sorted([k for k in self.keys[AES]])

    def reset(self):
        """For use in tests."""
        self.keys = deepcopy(self.template)
        self.loaded = False

    def reset_and_delete_keys(self, verbose: bool | None = None):
        """For use in tests.

        Use with extreme care!
        """
        verbose = self.verbose if verbose is None else verbose
        self.reset()
        write_msg(verbose, style.ERROR(" * Deleting encryption keys\n"))
        for filename in self.filenames:
            Path(filename).unlink(missing_ok=True)

    def get(self, k: str):
        return self.keys.get(k)

    def create_new_keys_or_raise(self):
        """Calls create after checking if allowed."""
        if auto_create_keys := get_auto_create_keys_from_settings():
            if not os.access(self.path, os.W_OK):
                raise DjangoCryptoFieldsError(
                    "Cannot auto-create encryption keys. Folder is not writeable."
                    f"Got {self.path}"
                )
            write_msg(
                self.verbose,
                style.SUCCESS(f" * settings.AUTO_CREATE_KEYS={auto_create_keys}.\n"),
            )
            self._create()
        else:
            raise DjangoCryptoFieldsKeysDoNotExist(
                f"Failed to find any encryption keys in path {self.path}. "
                "If this is your first time loading "
                "the project, set settings.AUTO_CREATE_KEYS=True and restart. "
                "Make sure the folder is writeable."
            )

    def _create(self) -> None:
        """Generates RSA and AES keys as per `filenames`."""
        if key_files_exist(self.path, self.key_prefix):
            raise DjangoCryptoFieldsKeyAlreadyExist(
                f"Not creating new keys. Encryption keys already exist. See {self.path}."
            )
        write_msg(self.verbose, style.WARNING(" * Generating new encryption keys ...\n"))
        self._create_rsa()
        self._create_aes()
        self._create_salt()
        write_msg(self.verbose, f"   Your new encryption keys are in {self.path}.\n")
        write_msg(self.verbose, style.ERROR("   DON'T FORGET TO BACKUP YOUR NEW KEYS!!\n"))
        write_msg(self.verbose, " Done generating new encryption keys.\n")

    def load_keys(self) -> None:
        """Loads all keys defined in self.filenames."""
        write_msg(
            self.verbose, style.WARNING(f" * Loading encryption keys from {self.path}\n")
        )
        if self.loaded:
            raise DjangoCryptoFieldsKeysAlreadyLoaded(
                f"Encryption keys have already been loaded. Path='{self.path}'."
            )
        self.load_rsa_keys()
        self.load_aes_keys()
        self.load_salt_keys()
        self.loaded = True
        write_msg(self.verbose, " Done loading encryption keys\n")

    def load_rsa_keys(self) -> None:
        """Loads RSA keys into _keys."""
        for access_mode, keys in self.keys[RSA].items():
            for key in keys:
                write_msg(self.verbose, f"  - loading {RSA}.{access_mode}.{key} ...\r")
                path = Path(self.keys[RSA][access_mode][key])
                with path.open(mode="rb") as f:
                    rsa_key = RSA_PUBLIC_KEY.importKey(f.read())
                    rsa_key = PKCS1_OAEP.new(rsa_key)
                    self.keys[RSA][access_mode][key] = rsa_key
                    self.update_rsa_key_info(rsa_key, access_mode)
                setattr(self, RSA + "_" + access_mode + "_" + key + "_key", rsa_key)
                write_msg(self.verbose, f"   - loading {RSA}.{access_mode}.{key} ... Done.\n")

    def load_aes_keys(self) -> None:
        """Decrypts and loads AES keys into _keys.

        Note: AES does not use a public key.
        """
        key = PRIVATE
        for access_mode in self.keys[AES]:
            write_msg(self.verbose, f"   - loading {AES}.{access_mode} ...\r")
            rsa_key = self.keys[RSA][access_mode][key]
            try:
                path = Path(self.keys[AES][access_mode][key])
            except KeyError:
                raise
            with path.open(mode="rb") as f:
                aes_key = rsa_key.decrypt(f.read())
            self.keys[AES][access_mode][key] = aes_key
            setattr(self, AES + "_" + access_mode + "_" + key + "_key", aes_key)
            write_msg(self.verbose, f"   - loading {AES}.{access_mode} ... Done.\n")

    def load_salt_keys(self) -> None:
        """Decrypts and loads salt keys into _keys."""
        for access_mode in self.keys[SALT]:
            write_msg(self.verbose, f"   - loading {SALT}.{access_mode} ...\r")
            attr = SALT + "_" + access_mode + "_" + PRIVATE
            rsa_key = self.keys[RSA][access_mode][PRIVATE]
            path = Path(self.keys[SALT][access_mode][PRIVATE])
            with path.open(mode="rb") as f:
                salt = rsa_key.decrypt(f.read())
                setattr(self, attr, salt)
            write_msg(self.verbose, f"   - loading {SALT}.{access_mode} ... Done.\n")

    def update_rsa_key_info(self, rsa_key, access_mode: str) -> None:
        """Stores info about the RSA key."""
        if self.loaded:
            raise DjangoCryptoFieldsKeysAlreadyLoaded(
                "Encryption keys have already been loaded."
            )
        mod_bits = number.size(rsa_key._key.n)
        self.rsa_key_info[access_mode] = {"bits": mod_bits}
        k = number.ceil_div(mod_bits, 8)
        self.rsa_key_info[access_mode].update({"bytes": k})
        h_len = rsa_key._hashObj.digest_size
        self.rsa_key_info[access_mode].update({"max_message_length": k - (2 * h_len) - 2})

    def _create_rsa(self) -> None:
        """Creates RSA keys."""
        for access_mode in self.keys.get(RSA):
            key = RSA_PUBLIC_KEY.generate(RSA_KEY_SIZE)
            pub = key.publickey()
            path = Path(self.keys.get(RSA).get(access_mode).get(PUBLIC))
            try:
                with path.open(mode="xb") as f1:
                    f1.write(pub.exportKey("PEM"))
                write_msg(self.verbose, f"   - Created new RSA {access_mode} key {path}\n")
                path = Path(self.keys.get(RSA).get(access_mode).get(PRIVATE))
                with open(path, "xb") as f2:
                    f2.write(key.exportKey("PEM"))
                write_msg(self.verbose, f"   - Created new RSA {access_mode} key {path}\n")
            except FileExistsError as e:
                raise DjangoCryptoFieldsKeyError(f"RSA key already exists. Got {e}")

    def _create_aes(self) -> None:
        """Creates AES keys and RSA encrypts them."""
        for access_mode in self.keys.get(AES):
            with Path(self.keys.get(RSA).get(access_mode).get(PUBLIC)).open(mode="rb") as f:
                rsa_key = RSA_PUBLIC_KEY.importKey(f.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            aes_key = Random.new().read(16)
            path = Path(self.keys.get(AES).get(access_mode).get(PRIVATE))
            with path.open(mode="xb") as f:
                f.write(rsa_key.encrypt(aes_key))
            write_msg(self.verbose, f"   - Created new AES {access_mode} key {path}\n")

    def _create_salt(self) -> None:
        """Creates a salt and RSA encrypts it."""
        for access_mode in self.keys.get(SALT):
            with Path(self.keys.get(RSA).get(access_mode).get(PUBLIC)).open(mode="rb") as f:
                rsa_key = RSA_PUBLIC_KEY.importKey(f.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            salt = Random.new().read(8)
            path = Path(self.keys.get(SALT).get(access_mode).get(PRIVATE))
            with path.open(mode="xb") as f:
                f.write(rsa_key.encrypt(salt))
            write_msg(self.verbose, f"   - Created new salt {access_mode} key {path}\n")


encryption_keys = Keys()
