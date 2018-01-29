from django.urls.conf import path
from django.views.generic.base import RedirectView

from .admin_site import encryption_admin

app_name = 'django_crypto_fields'

urlpatterns = [
    path('admin/django_crypto_fields/', encryption_admin.urls),
    path('admin/', encryption_admin.urls),
    path('', RedirectView.as_view(
        url='admin/django_crypto_fields/'), name='home_url'),
]
