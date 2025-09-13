from django.contrib import admin

from ..admin_site import encryption_admin
from ..utils import get_crypt_model_cls


@admin.register(get_crypt_model_cls(), site=encryption_admin)
class CryptModelAdmin(admin.ModelAdmin):
    date_hierarchy = "modified"

    fields = sorted(tuple(field.name for field in get_crypt_model_cls()._meta.fields))

    readonly_fields = tuple(field.name for field in get_crypt_model_cls()._meta.fields)

    list_display = ("algorithm", "hash", "modified", "hostname_modified")

    list_filter = ("algorithm", "modified", "hostname_modified")

    search_fields = ("hash",)
