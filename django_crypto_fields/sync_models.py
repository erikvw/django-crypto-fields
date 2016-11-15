from edc_sync.site_sync_models import site_sync_models
from edc_sync.sync_model import SyncModel


sync_models = [
    'django_crypto_fields.Crypt',
]

site_sync_models.register(sync_models, SyncModel)
