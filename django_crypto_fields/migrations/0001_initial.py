# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-05-02 19:19
from __future__ import unicode_literals

import django_extensions.db.fields
import django_revision.revision_field
import edc_model_fields.fields.hostname_modification_field
import edc_model_fields.fields.userfield
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Crypt",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    django_extensions.db.fields.CreationDateTimeField(
                        auto_now_add=True, verbose_name="created"
                    ),
                ),
                (
                    "modified",
                    django_extensions.db.fields.ModificationDateTimeField(
                        auto_now=True, verbose_name="modified"
                    ),
                ),
                (
                    "user_created",
                    edc_model_fields.fields.userfield.UserField(
                        editable=False, max_length=50, verbose_name="user created"
                    ),
                ),
                (
                    "user_modified",
                    edc_model_fields.fields.userfield.UserField(
                        editable=False, max_length=50, verbose_name="user modified"
                    ),
                ),
                (
                    "hostname_created",
                    models.CharField(
                        default="mac2-2.local",
                        editable=False,
                        help_text="System field. (modified on create only)",
                        max_length=50,
                    ),
                ),
                (
                    "hostname_modified",
                    edc_model_fields.fields.hostname_modification_field.HostnameModificationField(
                        editable=False,
                        help_text="System field. (modified on every save)",
                        max_length=50,
                    ),
                ),
                (
                    "revision",
                    django_revision.revision_field.RevisionField(
                        blank=True,
                        editable=False,
                        help_text="System field. Git repository tag:branch:commit.",
                        max_length=75,
                        null=True,
                        verbose_name="Revision",
                    ),
                ),
                (
                    "hash",
                    models.CharField(
                        db_index=True, max_length=128, unique=True, verbose_name="Hash"
                    ),
                ),
                ("secret", models.BinaryField(verbose_name="Secret")),
                (
                    "algorithm",
                    models.CharField(db_index=True, max_length=25, null=True),
                ),
                ("mode", models.CharField(db_index=True, max_length=25, null=True)),
            ],
            options={"verbose_name": "Crypt"},
        ),
        migrations.AlterUniqueTogether(
            name="crypt", unique_together=set([("hash", "algorithm", "mode")])
        ),
    ]
