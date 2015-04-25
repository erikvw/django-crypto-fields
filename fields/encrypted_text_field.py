from django.forms import widgets
from .local_aes_encryption_field import LocalAesEncryptionField


class EncryptedTextField(LocalAesEncryptionField):

    description = "Custom field for 'Text' form field, uses local AES"

    def formfield(self, **kwargs):
        defaults = {'widget': widgets.Textarea()}
        defaults.update(kwargs)
        return super(EncryptedTextField, self).formfield(**defaults)
