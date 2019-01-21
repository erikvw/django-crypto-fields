from django.forms import widgets

from .base_aes_field import BaseAesField


class EncryptedTextField(BaseAesField):

    description = "Custom field for 'Text' form field, uses local AES"

    def formfield(self, **kwargs):
        kwargs["widget"] = widgets.Textarea()
        return super(EncryptedTextField, self).formfield(**kwargs)
