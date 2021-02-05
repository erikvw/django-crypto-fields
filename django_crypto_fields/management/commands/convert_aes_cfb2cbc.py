import sys

from Crypto.Cipher import AES as AES_CIPHER
from django.apps import apps as django_apps
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ...constants import AES, LOCAL_MODE
from ...cryptor import Cryptor


class Command(BaseCommand):
    def add_arguments(self, parser):

        parser.add_argument(
            "--dry-run",
            action="store_true",
            dest="dry-run",
            default=False,
            help="dry run",
        )

    def __init__(self, *args, **kwargs):
        self._worklist = {}
        self.aes_decrypt = Cryptor(aes_encryption_mode=AES_CIPHER.MODE_CFB).aes_decrypt
        self.aes_encrypt = Cryptor(aes_encryption_mode=AES_CIPHER.MODE_CBC).aes_encrypt
        super(Command, self).__init__(*args, **kwargs)

    def handle(self, *args, **options):
        self.dry_run = options["dry-run"]
        if self.dry_run:
            sys.stdout.write(self.style.NOTICE("\nDry run. No changes will be made.\n"))
        error_msg = (
            "Default encryption mode must be explicitly "
            "set to AES.MODE_CFB in settings. "
            "(settings.AES_ENCRYPTION_MODE=AES.MODE_CFB)."
        )
        try:
            if settings.AES_ENCRYPTION_MODE != AES_CIPHER.MODE_CFB:
                raise CommandError(
                    "{} Got '{}'".format(error_msg, settings.AES_ENCRYPTION_MODE)
                )
        except AttributeError:
            raise CommandError(error_msg)
        self.update_crypts()
        self.stdout.write("Done.\n")
        self.stdout.write(
            self.style.NOTICE(
                "Important! DO NOT FORGET to remove attribute "
                "AES_ENCRYPTION_MODE from settings.py NOW.\n"
            )
        )

    def update_crypts(self):
        app = django_apps.get_app_config("django_crypto_fields")
        crypts = django_apps.get_model(*app.model).objects.filter(
            algorithm=AES, cipher_mode=AES_CIPHER.MODE_CFB
        )
        updated = 0
        skipped = 0
        total = crypts.count()
        sys.stdout.write("1. Crypt objects: {}\n".format(total))
        for index, obj in enumerate(crypts):
            value = self.aes_decrypt(obj.secret, LOCAL_MODE)
            if value:
                obj.secret = self.aes_encrypt(value, LOCAL_MODE)
                obj.cipher_mode = AES_CIPHER.MODE_CBC
                if not self.dry_run:
                    obj.save()
                updated += 1
            else:
                skipped += 1
            sys.stdout.write("  " + self.msg(total, index + 1, updated, skipped))
        sys.stdout.write("\n")

    def msg(self, total, index, updated, skipped):
        return "{index}/{total}. Updated: {updated}  Skipped : {skipped}\r"
