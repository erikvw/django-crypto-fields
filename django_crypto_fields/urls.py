from django.urls.conf import path

from .admin import crypto_fields_admin


urlpatterns = [
    path('admin/', crypto_fields_admin.urls),
]
