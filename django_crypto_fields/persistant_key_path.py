from django.apps import apps as django_apps

from .key_path import KeyPath


class DjangoCryptoFieldsKeyPathChangeError(Exception):
    pass


class lazy_property(object):
    '''
    meant to be used for lazy evaluation of an object attribute.
    property should represent non-mutable data, as it replaces itself.
    '''

    def __init__(self, fget):
        self.fget = fget
        self.func_name = fget.__name__

    def __get__(self, obj, cls):
        if obj is None:
            return None
        value = self.fget(obj)
        setattr(obj, self.func_name, value)
        return value


@lazy_property
def persist_key_path():
    app_config = django_apps.get_model('django_crypto_fields')
    model_cls = django_apps.get_model(app_config.key_reference_model)
    key_path = KeyPath()
    try:
        obj = model_cls.objects.all()[0]
    except IndexError:
        model_cls.objects.create(key_path=key_path)
    else:
        if obj.key_path != key_path:
            raise DjangoCryptoFieldsKeyPathChangeError()
