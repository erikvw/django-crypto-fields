from django.contrib.admin import AdminSite


class CryptoFieldsAdminSite(AdminSite):
    site_header = "Data Encryption"
    site_title = "Data Encryption"
    index_title = "Data Encryption"
    site_url = "/administration/"


encryption_admin = CryptoFieldsAdminSite(name="encryption_admin")
