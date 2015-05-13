from django.db.models import CharField


class SaltField (CharField):
    """
    HostnameCreationField

    By default, sets editable=False, blank=True, default=socket.gethostname()
    """

    description = "Custom field for hostname created"

    def __init__(self, *args, **kwargs):
        #base_crypter = BaseCrypter()
        kwargs.setdefault('editable', False)
        kwargs.setdefault('blank', False)
        kwargs.setdefault('max_length', 25)
        kwargs.setdefault('verbose_name', 'Salt')
        #kwargs.setdefault('default', base_crypter.make_random_salt())
        CharField.__init__(self, *args, **kwargs)

    def get_internal_type(self):
        return "CharField"

    def south_field_triple(self):
        "Returns a suitable description of this field for South."
        # We'll just introspect ourselves, since we inherit.
        from south.modelsinspector import introspector
        field_class = "django.db.models.fields.CharField"
        args, kwargs = introspector(self)
        return (field_class, args, kwargs)
