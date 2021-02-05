import os

from .constants import AES, LOCAL_MODE, PRIVATE, PUBLIC, RESTRICTED_MODE, RSA, SALT


class KeyFiles:
    """KEY_FILENAME names the algorithm (rsa, aes or salt), the mode (local and
    restricted) and the paths of the files to be created.

    The default KEY_FILENAME dictionary refers to 8 files.
       - 2 RSA local (public, private)
       - 2 RSA restricted  (public, private)
       - 1 AES local (RSA encrypted)
       - 1 AES restricted (RSA encrypted)
       - 1 salt local (RSA encrypted).
       - 1 salt restricted (RSA encrypted).
    """

    def __init__(self, key_path=None):
        self.key_path = key_path

    @property
    def key_filenames(self):
        return {
            RSA: {
                RESTRICTED_MODE: {
                    PUBLIC: os.path.join(
                        self.key_path.path,
                        self.key_path.key_prefix + "-rsa-restricted-public.pem",
                    ),
                    PRIVATE: os.path.join(
                        self.key_path.path,
                        self.key_path.key_prefix + "-rsa-restricted-private.pem",
                    ),
                },
                LOCAL_MODE: {
                    PUBLIC: os.path.join(
                        self.key_path.path,
                        self.key_path.key_prefix + "-rsa-local-public.pem",
                    ),
                    PRIVATE: os.path.join(
                        self.key_path.path,
                        self.key_path.key_prefix + "-rsa-local-private.pem",
                    ),
                },
            },
            AES: {
                LOCAL_MODE: {
                    PRIVATE: os.path.join(
                        self.key_path.path, self.key_path.key_prefix + "-aes-local.key"
                    )
                },
                RESTRICTED_MODE: {
                    PRIVATE: os.path.join(
                        self.key_path.path,
                        self.key_path.key_prefix + "-aes-restricted.key",
                    )
                },
            },
            SALT: {
                LOCAL_MODE: {
                    PRIVATE: os.path.join(
                        self.key_path.path, self.key_path.key_prefix + "-salt-local.key"
                    )
                },
                RESTRICTED_MODE: {
                    PRIVATE: os.path.join(
                        self.key_path.path,
                        self.key_path.key_prefix + "-salt-restricted.key",
                    )
                },
            },
        }

    @property
    def key_files_exist(self):
        key_files_exist = True
        for group, key_group in self.key_filenames.items():
            for mode, keys in key_group.items():
                for key in keys:
                    if not os.path.exists(self.key_filenames[group][mode][key]):
                        key_files_exist = False
                        break
        return key_files_exist

    @property
    def files(self):
        files = []
        for group, key_group in self.key_filenames.items():
            for mode, keys in key_group.items():
                for key in keys:
                    if os.path.exists(self.key_filenames[group][mode][key]):
                        files.append(self.key_filenames[group][mode][key])
        return files
