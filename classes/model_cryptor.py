import sys

from django.db.models import get_models, get_app
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class ModelCryptor(object):
    """A utility class to for a model with encrypted fields."""

    def encrypt_instance(self, instance, save=True):
        """ Encrypts the instance by calling save_base (not save!). """
        if save:
            instance.save_base(force_update=True, raw=True)
        return instance

    def get_encrypted_fields(self, model, **kwargs):
        """ Returns a list of field objects that use encryption.

        Keyword Arguments:
        field_name -- return a list with field object of this attname only. Name is ignored if not a field using encrytion.
        """
        from ..fields import BaseEncryptedField
        encrypted_fields = []
        field_name = kwargs.get('field_name', None)
        if field_name:
            if field_name in [field.attname for field in model._meta.fields if isinstance(field, BaseEncryptedField)]:
                encrypted_fields = [field for field in model._meta.fields if field.attname == field_name]
        if not encrypted_fields:
            encrypted_fields = [field for field in model._meta.fields if isinstance(field, BaseEncryptedField)]
        return encrypted_fields

    def get_encrypted_models(self, app_name, **kwargs):
        """ Returns a dictionary of model objects that contain encrypted fields
        in the format { model_name: {model, fields}}.
        """
        encrypted_models = {}
        try:
            app = get_app(app_name)
        except ImproperlyConfigured:
            app = None
        if app:
            for model in get_models(get_app(app_name)):
                encrypted_fields = self.get_encrypted_fields(model)
                if encrypted_fields:
                    encrypted_models[model._meta.object_name.lower()] = {'model': model,
                                                                         'encrypted_fields': encrypted_fields}
        return encrypted_models

    def get_all_encrypted_models(self):
        """ Returns a dictionary of models per app in the format {app_name: [encrypted_models, ...]}.
        """
        all_encrypted_models = {}
        for app_name in settings.INSTALLED_APPS:
            encrypted_models = self.get_encrypted_models(app_name)
            if encrypted_models:
                all_encrypted_models[app_name] = encrypted_models
        return all_encrypted_models

    def encrypt_model(self, model, save=True, **kwargs):
        """ Encrypts instances for a given model.

        Selects a queryset of unencrypted instances to operate on.

        Keyword Arguments:
        print_on_save -- print a message to stdout on each save (default: True)
        save_message -- message to print after each instance is saved which may include {0}
        and {1} for 'instance_count', 'instance_total' (default: 37/35666 instances encrypted ...).
        field_name -- filter unencrypted instances on the field object with this attname only.
        """
        print_on_save = kwargs.get('print_on_save', True)
        save_message = kwargs.get('save_message', '\r\x1b[K {0} / {1} instances encrypted...')
        unencrypted_instances, field_name = self.get_unencrypted_query_set(model, **kwargs)
        instance_total = model.objects.all().count()
        if not unencrypted_instances:
            if print_on_save:
                sys.stdout.write(' {0}/{0} instances already encrypted ({1})...'.format(instance_total,
                                                                                        field_name))
        else:
            unencrypted_instance_total = unencrypted_instances.count()
            if (instance_total - unencrypted_instance_total) > 0:
                sys.stdout.write(' {0}/{1} instances already encrypted ({2}).\n'.format(
                    (instance_total - unencrypted_instance_total),
                    instance_total,
                    field_name))
                sys.stdout.flush()
            instance_count = 0
            for unencrypted_instance in unencrypted_instances:
                instance_count += 1
                if save:
                    self.encrypt_instance(unencrypted_instance, save)
                if print_on_save:
                    try:
                        sys.stdout.write(save_message.format(instance_count,
                                                             unencrypted_instance_total))
                    except IndexError:
                        sys.stdout.write(save_message)
                    sys.stdout.flush()

    def get_unencrypted_values_set(self, model, **kwargs):
        """Returns a values set of unencrypted values."""
        kwargs.update({'query_set': 'values_set'})
        return self._get_unencrypted(model, **kwargs)

    def get_unencrypted_query_set(self, model, **kwargs):
        """Returns a queryset of unencrypted values."""
        return self._get_unencrypted(model, **kwargs)

    def _get_unencrypted(self, model, **kwargs):
        """ Returns a tuple of (query_set, field_name) where query_set may be a QuerySet
        or ValuesQuerySet where the value of field_name is not encrypted.

        Keyword Arguments:
        field_name -- filter on the field object with this attname only. Name is
                      ignored if not a field using encryption.
                      (default: name of first field that filters for a values/queryset
                      with unencrypted instances)
        query_set -- if \'values_set\', returns a  tuple of (ValueQuerySet, field_name)
                     where the values() field is the default field_name.
                     if \'query_set\', returns a QuerySet (default: 'query_set')

        Note: If the instance is in an inconsistent state (not every field encrypted),
        this may not be accurate. Check the model after running once.
        """
        field_name = kwargs.get('field_name', None)
        query_set = kwargs.get('query_set', 'query_set')
        encrypted_fields = self.get_encrypted_fields(model, field_name=field_name)
        return_set = None
        for encrypted_field in encrypted_fields:
            field_name = encrypted_field.attname
            field_startswith = '{0}__startswith'.format(encrypted_field.attname)
            encryption_prefix = encrypted_field.field_cryptor.cryptor.HASH_PREFIX
            field_exact = '{0}__exact'.format(encrypted_field.attname)
            if query_set == 'values_set':
                unencrypted_set = (model.objects.exclude(**{field_startswith: encryption_prefix}).exclude(**{field_exact: None}).exclude(**{field_exact: ''}).values('pk'))
            elif query_set == 'query_set':
                unencrypted_set = (model.objects.exclude(**{field_startswith: encryption_prefix}).exclude(**{field_exact: None}).exclude(**{field_exact: ''}))
            else:
                raise TypeError('Invalid value for keyword argument \'query_set\'. Got {0}'.format(query_set))
            if unencrypted_set.count() > 0:
                return_set = unencrypted_set
        if not return_set:
            return_set = model.objects.none().values(field_name)
        return return_set, field_name

    def is_instance_encrypted(self, **kwargs):
        """ Check if field values in instance are encrypted.

        Note: this is much slower than just saving the instance!!

        Keyword Arguments:
        instance -- a model instance (default: None)
        field_name -- filter on the field object with this attname only
        suppress_messages -- whether to print messages to stdout (default: False)

        """
        instance = kwargs.get('instance', None)
        if not instance:
            raise TypeError('Keyword argument \'instance\' cannot be None')
        return self._is_encrypted(**kwargs)

    def is_model_encrypted(self, **kwargs):
        """ Check if instances in model are encrypted.
        Note: this is much slower than just saving the instances!!

        Keyword Arguments:
        model -- checks all instances within model (default: None)
        field_name -- filter on the field object with this attname only
        suppress_messages -- whether to print messages to stdout (default: False)

        """
        model = kwargs.get('model', None)
        if not model:
            raise TypeError('Keyword argument \'model\' cannot be None')
        return self._is_encrypted(**kwargs)

    def _is_encrypted(self, **kwargs):
        """ Check if field values in instance/model are encrypted.

        ..note:: Note: this is much slower than just saving the instance!!

        Keyword Arguments:
            instance -- limits the check to just this model instance (default: None)
            model -- checks all instances within model (default: None)
            field_name -- filter model or instance on the field object with this attname only
            suppress_messages -- whether to print messages to stdout (default: False)
        """
        instance = kwargs.get('instance', None)
        model = kwargs.get('model', None)
        field_name = kwargs.get('field_name', None)
        suppress_messages = kwargs.get('suppress_messages', False)
        model_name = model._meta.object_name.lower()
        if instance and model:
            raise TypeError('One of keyword arguments \'model\' and \instance\' must be None')
        if instance:
            model = instance.__class__
        else:
            try:
                instance = model.objects.all()[0]
            except:
                instance = None
        if not instance:
            is_encrypted = True
            if not suppress_messages:
                print ('(*) {model_name}. (empty!)').format(model_name=model_name,
                                                            field_name=field_name)
        else:
            encrypted_fields = self.get_encrypted_fields(model)
            if not encrypted_fields:
                if not suppress_messages:
                    print '{model_name} does not use field encryption.'.format(model_name=model_name)
                is_encrypted = None
            else:
                unencrypted_values_set, field_name = self.get_unencrypted_values_set(model, field_name=field_name)
                if unencrypted_values_set.count() != 0:
                    is_encrypted = False
                    if not suppress_messages:
                        if unencrypted_values_set.count() == model.objects.all().count():
                            if not suppress_messages:
                                print ('( ) {model_name}').format(model_name=model_name,
                                                                  field_name=field_name)
                        else:
                            print ('(?) {model_name}: {count} of {total} '
                                   'rows not encrypted (based on {field_name})').format(
                                model_name=model_name,
                                count=unencrypted_values_set.count(),
                                total=model.objects.all().count(),
                                field_name=field_name)
                elif model.objects.all().count() == 0:
                    is_encrypted = True
                    if not suppress_messages:
                        print ('(*) {model_name}. (empty!)').format(model_name=model_name,
                                                                    field_name=field_name)
                else:
                    is_encrypted = True
                    if not suppress_messages:
                        print ('(*) {model_name}').format(model_name=model_name,
                                                          field_name=field_name)
        return is_encrypted
