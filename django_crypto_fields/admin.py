from django.apps import apps as django_apps
from django.contrib import admin

from .admin_site import encryption_admin


app_config = django_apps.get_app_config('django_crypto_fields')
Crypt = django_apps.get_model(app_config.model)
KeyReference = django_apps.get_model(app_config.key_reference_model)


@admin.register(Crypt, site=encryption_admin)
class CryptModelAdmin(admin.ModelAdmin):

    date_hierarchy = 'modified'

    fields = sorted([field.name for field in Crypt._meta.fields])

    readonly_fields = [field.name for field in Crypt._meta.fields]

    list_display = ('algorithm', 'hash', 'modified', 'hostname_modified')

    list_filter = ('algorithm', 'modified', 'hostname_modified')

    search_fields = ('hash', )


@admin.register(KeyReference, site=encryption_admin)
class KeyReferenceAdmin(admin.ModelAdmin):
    fields = ('key_path', 'key_filenames', 'created')
    readonly_fields = fields
    list_display = ('key_path', 'created')
    list_display_links = ('key_path', )
