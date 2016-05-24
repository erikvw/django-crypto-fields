from django.contrib import admin
from django.contrib.admin import AdminSite
from django_crypto_fields.models import Crypt


class CryptoFieldsAdminSite(AdminSite):
    """
    For example:
        add to urls:
            url(r'^call_manager/', call_manager_admin.urls),
        then:
            >>> reverse('call_manager_admin:edc_call_manager_call_add')
            '/call_manager/edc_call_manager/call/add/'
    """
    site_header = 'Data Encryption Administration'
    site_title = 'Data Encryption Administration'
    index_title = 'Data Encryption'
    site_url = '/crypto_fields/'
encryption_admin = CryptoFieldsAdminSite(name='encryption_admin')


@admin.register(Crypt, site=encryption_admin)
class CryptAdmin(admin.ModelAdmin):
    search_fields = ('hash', )
