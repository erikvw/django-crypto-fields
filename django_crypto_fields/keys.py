from __future__ import annotations

import os
import sys
from copy import deepcopy
from pathlib import Path, PurePath

from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA as RSA_PUBLIC_KEY
from Cryptodome.Util import number
from django.conf import settings
from django.core.management.color import color_style

from .constants import (
    AES,
    LOCAL_MODE,
    PRIVATE,
    PUBLIC,
    RESTRICTED_MODE,
    RSA,
    RSA_KEY_SIZE,
    SALT,
)
from .exceptions import (
    DjangoCryptoFieldsError,
    DjangoCryptoFieldsKeyAlreadyExist,
    DjangoCryptoFieldsKeyError,
    DjangoCryptoFieldsKeysAlreadyLoaded,
    DjangoCryptoFieldsKeysDoNotExist,
)
from .key_path import KeyPath, persist_key_path_or_raise
from .utils import get_auto_create_keys_from_settings, get_key_prefix_from_settings


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
        self.files: list[str] = []
        self.path: PurePath = KeyPath().path
        self.template: dict[str, dict[str, dict[str, RSA_PUBLIC_KEY]]] = {
            RSA: {
                RESTRICTED_MODE: {
                    PUBLIC: self.path / (self.key_prefix + "-rsa-restricted-public.pem"),
                    PRIVATE: self.path / (self.key_prefix + "-rsa-restricted-private.pem"),
                },
                LOCAL_MODE: {
                    PUBLIC: self.path / (self.key_prefix + "-rsa-local-public.pem"),
                    PRIVATE: self.path / (self.key_prefix + "-rsa-local-private.pem"),
                },
            },
            AES: {
                LOCAL_MODE: {PRIVATE: self.path / (self.key_prefix + "-aes-local.key")},
                RESTRICTED_MODE: {
                    PRIVATE: self.path / (self.key_prefix + "-aes-restricted.key"),
                },
            },
            SALT: {
                LOCAL_MODE: {PRIVATE: self.path / (self.key_prefix + "-salt-local.key")},
                RESTRICTED_MODE: {
                    PRIVATE: self.path / (self.key_prefix + "-salt-restricted.key"),
                },
            },
        }
        for _, v in self.template.items():
            for _, _v in v.items():
                for _, fname in _v.items():
                    self.files.append(fname)
        self.initialize()

    def initialize(self):
        """Load keys and create if necessary."""
        style = color_style()
        if not getattr(settings, "DJANGO_CRYPTO_FIELDS_INITIALIZE", True):
            sys.stdout.write(
                style.ERROR(
                    " * NOT LOADING ENCRYPTION KEYS, see "
                    "settings.DJANGO_CRYPTO_FIELDS_INITIALIZE\n"
                )
            )
        else:
            self.write("Loading encryption keys\n")
            self.keys = deepcopy(self.template)
            persist_key_path_or_raise()
            if not self.key_files_exist:
                if auto_create_keys := get_auto_create_keys_from_settings():
                    if not os.access(self.path, os.W_OK):
                        raise DjangoCryptoFieldsError(
                            "Cannot auto-create encryption keys. Folder is not writeable."
                            f"Got {self.path}"
                        )
                    self.write(
                        style.SUCCESS(f" * settings.AUTO_CREATE_KEYS={auto_create_keys}.\n")
                    )
                    self.create()
                else:
                    raise DjangoCryptoFieldsKeysDoNotExist(
                        f"Failed to find any encryption keys in path {self.path}. "
                        "If this is your first time loading "
                        "the project, set settings.AUTO_CREATE_KEYS=True and restart. "
                        "Make sure the folder is writeable."
                    )
            self.load_keys()
            self.rsa_modes_supported = sorted([k for k in self.keys[RSA]])
            self.aes_modes_supported = sorted([k for k in self.keys[AES]])
            self.write("  Done loading encryption keys\n")

    def reset(self, delete_all_keys: str = None, verbose: bool = None):
        """Use with extreme care!"""
        verbose = True if verbose is None else verbose
        self.keys = deepcopy(self.template)
        self.loaded = False
        if delete_all_keys == "delete_all_keys":
            if verbose:
                style = color_style()
                sys.stdout.write(style.ERROR(" * Deleting encryption keys\n"))
            for file in encryption_keys.files:
                try:
                    Path(file).unlink()
                except FileNotFoundError:
                    pass

    def get(self, k: str):
        return self.keys.get(k)

    def create(self) -> None:
        """Generates RSA and AES keys as per `filenames`."""
        style = color_style()
        if self.key_files_exist:
            raise DjangoCryptoFieldsKeyAlreadyExist(
                f"Not creating new keys. Encryption keys already exist. See {self.path}."
            )
        self.write(style.WARNING(" * Generating new encryption keys ...\n"))
        self._create_rsa()
        self._create_aes()
        self._create_salt()
        self.write("    Done generating new encryption keys.\n")
        self.write(f"    Your new encryption keys are in {self.path}.\n")
        self.write(style.ERROR("    DON'T FORGET TO BACKUP YOUR NEW KEYS!!\n"))

    def write(self, msg: str):
        if self.verbose:
            sys.stdout.write(msg)

    def load_keys(self) -> None:
        """Loads all keys defined in self.filenames."""
        if self.loaded:
            raise DjangoCryptoFieldsKeysAlreadyLoaded(
                f"Encryption keys have already been loaded. Path='{self.path}'."
            )
        self.write(f" * loading keys from {self.path}\n")
        for mode, keys in self.keys[RSA].items():
            for key in keys:
                self.write(f" * loading {RSA}.{mode}.{key} ...\r")
                self.load_rsa_key(mode, key)
                self.write(f" * loading {RSA}.{mode}.{key} ... Done.\n")
        for mode in self.keys[AES]:
            self.write(f" * loading {AES}.{mode} ...\r")
            self.load_aes_key(mode)
            self.write(f" * loading {AES}.{mode} ... Done.\n")
        for mode in self.keys[SALT]:
            self.write(f" * loading {SALT}.{mode} ...\r")
            self.load_salt_key(mode, key)
            self.write(f" * loading {SALT}.{mode} ... Done.\n")
        self.loaded = True

    def load_rsa_key(self, mode, key) -> None:
        """Loads an RSA key into _keys."""
        if self.loaded:
            raise DjangoCryptoFieldsKeysAlreadyLoaded(
                "Encryption keys have already been loaded."
            )
        path = Path(self.keys[RSA][mode][key])
        with path.open(mode="rb") as f:
            rsa_key = RSA_PUBLIC_KEY.importKey(f.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            self.keys[RSA][mode][key] = rsa_key
            self.update_rsa_key_info(rsa_key, mode)
        setattr(self, RSA + "_" + mode + "_" + key + "_key", rsa_key)

    def load_aes_key(self, mode) -> None:
        """Decrypts and loads an AES key into _keys.

        Note: AES does not use a public key.
        """
        if self.loaded:
            raise DjangoCryptoFieldsKeysAlreadyLoaded(
                "Encryption keys have already been loaded."
            )
        key = PRIVATE
        rsa_key = self.keys[RSA][mode][key]
        try:
            path = Path(self.keys[AES][mode][key])
        except KeyError:
            raise
        with path.open(mode="rb") as f:
            aes_key = rsa_key.decrypt(f.read())
        self.keys[AES][mode][key] = aes_key
        setattr(self, AES + "_" + mode + "_" + key + "_key", aes_key)

    def load_salt_key(self, mode, key) -> None:
        """Decrypts and loads a salt key into _keys."""
        if self.loaded:
            raise DjangoCryptoFieldsKeysAlreadyLoaded(
                "Encryption keys have already been loaded."
            )
        attr = SALT + "_" + mode + "_" + PRIVATE
        rsa_key = self.keys[RSA][mode][PRIVATE]
        path = Path(self.keys[SALT][mode][PRIVATE])
        with path.open(mode="rb") as f:
            salt = rsa_key.decrypt(f.read())
            setattr(self, attr, salt)

    def update_rsa_key_info(self, rsa_key, mode) -> None:
        """Stores info about the RSA key."""
        if self.loaded:
            raise DjangoCryptoFieldsKeysAlreadyLoaded(
                "Encryption keys have already been loaded."
            )
        mod_bits = number.size(rsa_key._key.n)
        self.rsa_key_info[mode] = {"bits": mod_bits}
        k = number.ceil_div(mod_bits, 8)
        self.rsa_key_info[mode].update({"bytes": k})
        h_len = rsa_key._hashObj.digest_size
        self.rsa_key_info[mode].update({"max_message_length": k - (2 * h_len) - 2})

    def _create_rsa(self, mode=None) -> None:
        """Creates RSA keys."""
        modes = [mode] if mode else self.keys.get(RSA)
        for mode in modes:
            key = RSA_PUBLIC_KEY.generate(RSA_KEY_SIZE)
            pub = key.publickey()
            path = Path(self.keys.get(RSA).get(mode).get(PUBLIC))
            try:
                with path.open(mode="xb") as f1:
                    f1.write(pub.exportKey("PEM"))
                self.write(f" - Created new RSA {mode} key {path}\n")
                path = Path(self.keys.get(RSA).get(mode).get(PRIVATE))
                with open(path, "xb") as f2:
                    f2.write(key.exportKey("PEM"))
                self.write(f" - Created new RSA {mode} key {path}\n")
            except FileExistsError as e:
                raise DjangoCryptoFieldsKeyError(f"RSA key already exists. Got {e}")

    def _create_aes(self, mode=None) -> None:
        """Creates AES keys and RSA encrypts them."""
        modes = [mode] if mode else self.keys.get(AES)
        for mode in modes:
            with Path(self.keys.get(RSA).get(mode).get(PUBLIC)).open(mode="rb") as rsa_file:
                rsa_key = RSA_PUBLIC_KEY.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            aes_key = Random.new().read(16)
            path = Path(self.keys.get(AES).get(mode).get(PRIVATE))
            with path.open(mode="xb") as f:
                f.write(rsa_key.encrypt(aes_key))
            self.write(f" - Created new AES {mode} key {path}\n")

    def _create_salt(self, mode=None) -> None:
        """Creates a salt and RSA encrypts it."""
        modes = [mode] if mode else self.keys.get(SALT)
        for mode in modes:
            with Path(self.keys.get(RSA).get(mode).get(PUBLIC)).open(mode="rb") as rsa_file:
                rsa_key = RSA_PUBLIC_KEY.importKey(rsa_file.read())
            rsa_key = PKCS1_OAEP.new(rsa_key)
            salt = Random.new().read(8)
            path = Path(self.keys.get(SALT).get(mode).get(PRIVATE))
            with path.open(mode="xb") as f:
                f.write(rsa_key.encrypt(salt))
            self.write(f" - Created new salt {mode} key {path}\n")

    @property
    def key_files_exist(self) -> bool:
        key_files_exist = False
        for group, key_group in self.keys.items():
            for mode, keys in key_group.items():
                for key in keys:
                    if Path(self.keys[group][mode][key]).exists():
                        key_files_exist = True
                        break
        return key_files_exist


encryption_keys = Keys()
