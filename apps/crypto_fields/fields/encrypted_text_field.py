from django.forms import widgets

from .aes_field import AesField


class EncryptedTextField(AesField):

    description = "Custom field for 'Text' form field, uses local AES"

    def formfield(self, **kwargs):
        kwargs['widget'] = widgets.Textarea()
        return super(EncryptedTextField, self).formfield(**kwargs)
