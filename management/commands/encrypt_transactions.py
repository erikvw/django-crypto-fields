from django.core.management.base import BaseCommand, CommandError
from django.db.models import get_model
from ...classes import FieldCryptor


#usage: python manage.py encrypt_transactions outgoing/incoming
class Command(BaseCommand):
    args = '<model_name>'
    help = 'Encrypt Incoming and outgoing transactions.'

    def handle(self, *args, **options):
        field_cryptor = FieldCryptor('aes', 'local')
        model = None
        if not args:
            self.stdout.write('Encrypting both incoming and outgoing.\n')
            self.stdout.write('Starting with incoming.\n')
            self.encrypt_tx(field_cryptor, get_model('sync', 'incomingtransaction'))

            self.stdout.write('Processing with outgoing.\n')
            self.encrypt_tx(field_cryptor, get_model('sync', 'outgoingtransaction'))
        else:
            for model_name in args:
                if model_name.lower() == 'outgoing':
                    model = get_model('sync', 'outgoingtransaction')
                elif model_name.lower() == 'incoming':
                    model = get_model('sync', 'incomingtransaction')
                else:
                    raise CommandError('Model {} not found'.format(model_name))
            if model:
                self.encrypt_tx(field_cryptor, model)

    def encrypt_tx(self, field_cryptor, model):
        count = model.objects.exclude(tx__startswith='enc1:::').count()
        instance_count = 0
        self.stdout.write('{0} Unencrypted {1} transactions found.\n'.format(model.__name__,count))
        for transaction in model.objects.exclude(tx__startswith='enc1:::'):
            instance_count += 1
            #tx = str(transaction.tx)
            transaction.tx = field_cryptor.encrypt(transaction.tx)
            transaction.save()

            self.stdout.write('\r\x1b[K {0} / {1} transactions'
                                  ' ...'.format(instance_count, count))
            self.stdout.flush()

        self.stdout.write('done.\n')
