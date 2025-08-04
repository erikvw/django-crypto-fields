from django.urls.conf import path
from django.views.generic.base import RedirectView

from .admin_site import encryption_admin

app_name = "django_crypto_fields"

urlpatterns = [
    path("admin/", encryption_admin.urls),
    path("", RedirectView.as_view(url="admin/"), name="home_url"),
]
