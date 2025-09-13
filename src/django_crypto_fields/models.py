from django.db import models
from django_audit_fields.models import AuditUuidModelMixin

from .fields import BaseField


class CryptoMixin(models.Model):
    """Model mixin for a user model that needs to list it's
    encrypted fields.
    """

    class Meta:
        abstract = True

    @classmethod
    def encrypted_fields(cls):
        return [fld.name for fld in cls._meta.fields if isinstance(fld, BaseField)]


class CryptModelManager(models.Manager):
    def get_by_natural_key(self, value_as_hash, algorithm, mode):
        return self.get(hash=value_as_hash, algorithm=algorithm, mode=mode)


class Crypt(AuditUuidModelMixin, models.Model):
    """A `secrets` lookup model searchable by hash."""

    hash = models.CharField(verbose_name="Hash", max_length=128, db_index=True)

    # causes problems with Postgres!!
    secret = models.BinaryField(verbose_name="Secret")

    algorithm = models.CharField(max_length=25, db_index=True)

    mode = models.CharField(max_length=25, db_index=True)

    cipher_mode = models.IntegerField(
        null=True, help_text="pycryptodomex AES cipher mode (e.g. MODE_CBC)"
    )

    objects = CryptModelManager()

    class Meta:
        verbose_name = "Crypt"
        unique_together = (("hash", "algorithm", "mode"),)
        indexes = (models.Index(fields=["hash", "algorithm", "mode"]),)

    def natural_key(self):
        return (
            self.hash,
            self.algorithm,
            self.mode,
        )
