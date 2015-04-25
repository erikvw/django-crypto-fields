from django.contrib import admin
from ..models import Crypt


class CryptAdmin (admin.ModelAdmin):

    list_display = ('hash', 'created', 'modified')
    list_filter = ('created', 'modified')
    search_fields = ('hash',)

admin.site.register(Crypt, CryptAdmin)
