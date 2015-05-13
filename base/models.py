from django.db import models
from django_extensions.db.models import TimeStampedModel

from .fields import HostnameCreationField, HostnameModificationField, UUIDAutoField


class BaseModel(TimeStampedModel):

    id = UUIDAutoField(
        primary_key=True,
        help_text="system field. uuid primary key."
    )

    user_created = models.CharField(
        max_length=250,
        verbose_name='user created',
        editable=False,
        default="",
        db_index=True,
        help_text="system field."
    )

    user_modified = models.CharField(
        max_length=250,
        verbose_name='user modified',
        editable=False,
        default="",
        db_index=True,
        help_text="system field.",
    )

    hostname_created = HostnameCreationField(
        db_index=True,
        help_text="system field.",
    )

    hostname_modified = HostnameModificationField(
        db_index=True,
        help_text="system field.",
    )

    class Meta:
        abstract = True
