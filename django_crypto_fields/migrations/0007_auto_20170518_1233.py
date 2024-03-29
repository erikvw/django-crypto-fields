# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-05-18 12:33
from __future__ import unicode_literals

import edc_model_fields.fields.userfield
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("django_crypto_fields", "0006_auto_20170328_0728")]

    operations = [
        migrations.AlterField(
            model_name="crypt",
            name="user_created",
            field=edc_model_fields.fields.userfield.UserField(
                blank=True,
                help_text="Updated by admin.save_model",
                max_length=50,
                verbose_name="user created",
            ),
        ),
        migrations.AlterField(
            model_name="crypt",
            name="user_modified",
            field=edc_model_fields.fields.userfield.UserField(
                blank=True,
                help_text="Updated by admin.save_model",
                max_length=50,
                verbose_name="user modified",
            ),
        ),
    ]
