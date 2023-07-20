from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .fields import BaseField


def has_encrypted_fields(model) -> bool:
    for field in model._meta.get_fields():
        if hasattr(field, "field_cryptor"):
            return True
    return False


def get_encrypted_fields(model) -> list[BaseField]:
    encrypted_fields = []
    for field in model._meta.get_fields():
        if hasattr(field, "field_cryptor"):
            encrypted_fields.append(field)
    return encrypted_fields
