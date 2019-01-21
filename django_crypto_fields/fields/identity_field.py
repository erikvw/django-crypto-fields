from .base_rsa_field import BaseRsaField


class IdentityField(BaseRsaField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("null", False)
        kwargs.setdefault("blank", False)
        super().__init__(*args, **kwargs)
