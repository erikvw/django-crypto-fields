from optparse import make_option
from django.core.management.base import BaseCommand, CommandError
from django.db.models import get_model
from ...fields import BaseEncryptedField


class Command(BaseCommand):

    args = '--field <app.model.fieldname> --old-class <classname> --new-class <classname>'
    help = 'Convert the values of encrypted fields to use a new field class. New class will be confirmed'
    option_list = BaseCommand.option_list + (
        make_option('--field',
            action='store_true',
            dest='field',
            default=False,
            help='app.model.fieldname to convert. Not case sensitive.'),
        )
    option_list += (
        make_option('--old-class',
            action='store_true',
            dest='old_class',
            default=False,
            help='Original field class. Existing values were encrypted with this field class cryptor algorithm.'),
        )
    option_list += (
        make_option('--new-class',
            action='store_true',
            dest='new_class',
            default=False,
            help='New field class (confirmed). This field class will re-encrypt existing values using its cryptor algorithm.'),
        )

    def __init__(self, *args, **kwargs):
        self.app_label = None
        self.model_name = None
        self.field_name = None
        super(Command, self).__init__(*args, **kwargs)

    def handle(self, *args, **options):
        if options['field']:
            self.set_field(options['field'])
        elif options['old_class']:
            self.set_old_class(options['old_class'])
        elif options['old_class']:
            self.set_new_class(options['new_class'])
        else:
            self.set_field()

    def set_field(self):
        try:
            app_name, model_name, field_name = self.field_parameter.split('.').lower()
            self.model = get_model(app_name, model_name)
            for field in self.model._meta.fields:
                if field.attname == field_name:
                    if isinstance(field, BaseEncryptedField):
                        if field.__class__.name == self.new_class_parameter:
                            pass
        except:
            raise CommandError('Incorrect format or invalid value for field parameter. Got {0}. Format is app_name.model_name.fieldname'.format(field.lower()))

    def field(self, value):
        self.field_parameter = value

    def new_class(self, value):
        self.new_class_parameter = value

    def old_class(self, value):
        self.old_class_parameter = value
