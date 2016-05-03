from django.contrib import admin
from django_crypto_fields.models import Crypt


@admin.register(Crypt)
class CryptAdmin(admin.ModelAdmin):
    search_fields = ('hash', )
