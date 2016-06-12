from django.apps import apps as django_apps
from django.contrib import admin
from django.contrib.admin import AdminSite
# from django_crypto_fields.models import Crypt


Crypt = django_apps.get_model(*django_apps.get_app_config('django_crypto_fields').model)


class CryptoFieldsAdminSite(AdminSite):
    """
    For example:
        add to urls:
            url(r'^admin/', encryption_admin.urls),
        then:
            >>> reverse('encryption_admin:django_crypto_fields_crypt_add')
            '/admin/django_crypto_fields/crypt/add/'
    """
    site_header = 'Data Encryption Administration'
    site_title = 'Data Encryption Administration'
    index_title = 'Data Encryption'
    site_url = '/crypto_fields/'
crypto_fields_admin = CryptoFieldsAdminSite(name='encryption_admin')


@admin.register(Crypt, site=crypto_fields_admin)
class CryptAdmin(admin.ModelAdmin):

    date_hierarchy = 'modified'

    fields = sorted([field.name for field in Crypt._meta.fields])

    readonly_fields = [field.name for field in Crypt._meta.fields]

    list_display = ('algorithm', 'hash', 'modified', 'hostname_modified')

    list_filter = ('algorithm', 'modified', 'hostname_modified')

    search_fields = ('hash', )
