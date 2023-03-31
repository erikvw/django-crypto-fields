def has_encrypted_fields(model):
    for field in model._meta.get_fields():
        if hasattr(field, "field_cryptor"):
            return True
    return False
