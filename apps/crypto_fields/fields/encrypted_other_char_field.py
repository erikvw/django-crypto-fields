from .local_aes_encryption_field import LocalAesEncryptionField


class EncryptedOtherCharField(LocalAesEncryptionField):

    description = "Custom field for 'Other specify' form field"

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('blank', True)
        kwargs.setdefault('verbose_name', '...if "Other", specify')
        super(EncryptedOtherCharField, self).__init__(*args, **kwargs)
