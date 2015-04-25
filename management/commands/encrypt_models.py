from datetime import datetime
from optparse import make_option
from django.core.management.base import BaseCommand, CommandError
from ...classes import ModelCryptor, FieldCryptor
from ...models import Crypt


class Command(BaseCommand):

    args = '--list-models --list-fields --check --dry-run --verify-lookup --decribe'
    help = 'Encrypt fields within any INSTALLED_APP model using an encrypted field object.'
    option_list = BaseCommand.option_list + (
        make_option('--encrypt',
            action='store_true',
            dest='encrypt',
            default=False,
            help=('Encrypts data in all models that use encryption. (DATA WILL BE CHANGED.).')),
         )
    option_list += (
        make_option('--list-models',
            action='store_true',
            dest='list',
            default=False,
            help=('Lists models using encryption. (Safe. Lists only, does not encrypt any data).')),
        )
    option_list += (
        make_option('--check',
            action='store_true',
            dest='check',
            default=False,
            help=('Checks if all instances of each model are encrypted. (checks only, does not encrypt any data).')),
        )
    option_list += (
        make_option('--list-fields',
            action='store_true',
            dest='list_fields',
            default=False,
            help=('Lists the fields in each model using encryption. (Safe. Lists only, '
                  'does not encrypt any data)..')),
        )
    option_list += (
            make_option('--dry-run',
                action='store_true',
                dest='dry_run',
                default=False,
                help=('Encrypts without saving. (Safe. Does not encrypt any data)')),
            )
    option_list += (
            make_option('--verify-lookup',
                action='store_true',
                dest='verify_lookup',
                default=False,
                help=('Verifies secrets and hashing in lookup table, bhp_crypto.models.crypt. '
                      '(Safe. Does not encrypt any data)')),
            )
    option_list += (
            make_option('--describe-plan',
                action='store_true',
                dest='describe',
                default=False,
                help=('Describes encryption plan by showing number of models, fields and '
                      'instances to be encrypted. (Safe. Does not encrypt any data)')),
            )

    def handle(self, *args, **options):

        self.save = True
        if options['dry_run']:
            self.save = False
            self.encrypt(False)
        elif options['list']:
            self._list_encrypted_models()
        elif options['check']:
            self._check_models_encrypted()
        elif options['list_fields']:
            self._list_encrypted_fields()
        elif options['describe']:
            self.describe()
        elif options['verify_lookup']:
            self.verify_lookup()
        elif options['encrypt']:
            self.encrypt()
        else:
            raise CommandError('Unknown option, Try --help for a list of valid options')

    def encrypt(self, save=True):
        """For each app, encrypts all models with field objects that use encryption."""
        self._list_encrypted_models(count_only=True)
        self.describe()
        if not save:
            self.stdout.write('This is a dry-run, no data will be changed.\n')
        msg = 'No models to encrypt.'
        n = 0
        model_cryptor = ModelCryptor()
        all_encrypted_models = model_cryptor.get_all_encrypted_models()
        if all_encrypted_models:
            for encrypted_models in all_encrypted_models.itervalues():
                for encrypted_model in encrypted_models.itervalues():
                    self._encrypt_model(encrypted_model['model'], save)
            msg = 'Complete. {0} models encrypted.\n'.format(n)
        self.stdout.write(msg)
        self.stdout.flush()

    def _encrypt_model(self, model, save=True):
        """ Encrypts all instances for given model that are not yet encrypted."""
        model_cryptor = ModelCryptor()
        app_name = model._meta.app_label
        model_name = model._meta.object_name.lower()
        start = datetime.today()
        self.stdout.write('Encrypting {app_name}.{model}...'
                          'started {start}\n'.format(app_name=app_name,
                                                     model=model_name,
                                                     start=start.strftime("%H:%M:%S")))
        model_cryptor.encrypt_model(model, save)
        end = datetime.today()
        hours, remainder = divmod((end - start).seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.stdout.write('done in {0}:{1}:{2}.\n'.format(str(hours).rjust(2, '0'),
                                                          str(minutes).rjust(2, '0'),
                                                          str(seconds).rjust(2, '0')))
        self.stdout.flush()

    def _list_encrypted_models(self, **kwargs):
        """Lists names of models that contain field objects that use encryption.

        Keyword Arguments:
        list-fields -- include for each model with the names of the fields that
                       use encryption. (default: False)
        count_only -- just list the model count. (default: False)
        """
        list_fields = kwargs.get('list_fields', False)
        count_only = kwargs.get('count_only', False)
        model_cryptor = ModelCryptor()
        n = 0
        field_count = 0
        instance_count_total = 0
        all_encrypted_models = model_cryptor.get_all_encrypted_models()
        for app_name, encrypted_models in all_encrypted_models.iteritems():
            for meta in encrypted_models.itervalues():
                model = meta['model']
                encrypted_fields = meta['encrypted_fields']
                field_count += len(meta['encrypted_fields'])
                n += 1
                instance_count = model.objects.all().count()
                instance_count_total += instance_count
                if not count_only:
                    self.stdout.write('{app_name}.{model}. {encrypted_fields} '
                                      'fields. ({records} records)\n'.format(app_name=app_name,
                                                         model=model._meta.object_name.lower(),
                                                         encrypted_fields=len(encrypted_fields),
                                                         records=instance_count))
                if list_fields:
                    self.stdout.write('  {encrypted_fields}\n'.format(encrypted_fields=' \n  '.join(([' '.join((field.attname, '-'.join((field.algorithm, field.mode)))) for field in encrypted_fields]))))

        if not count_only:
            self.stdout.write('{0} models use encryption in {1} fields.\n'.format(n, field_count))
        return {'models': n, 'fields': field_count, 'instances': instance_count_total}

    def _list_encrypted_fields(self):
        """ Lists each model with the names of the fields that use encryption. """
        self._list_encrypted_models(list_fields=True)

    def _check_models_encrypted(self):
        """Checks the encryption status of each instance in each model. """
        model_cryptor = ModelCryptor()
        all_encrypted_models = model_cryptor.get_all_encrypted_models()
        for app_name, encrypted_models in all_encrypted_models.iteritems():
            print '\n' + app_name.upper()
            for meta in encrypted_models.itervalues():
                model = meta['model']
                model_cryptor.is_model_encrypted(model=model)

    def verify_lookup(self, **kwargs):
        """Verifies the hashes and secrets in the lookup model Crypt by decrypting the secrets,
        hashing them and comparing to the stored hashes.
        """
        print_messages = kwargs.get('print_messages', True)
        if print_messages:
            self.stdout.write('Verify secrets and hashes stored in lookup model '
                              '(bhp_crypto.models.crypt)...\n')
            self.stdout.write('Verify from newest to oldest.\n')
        n = 0
        verified = 0
        failed_hash = 0
        failed_decrypt = 0
        total = Crypt.objects.all().count()
        for instance in Crypt.objects.all().order_by('-modified'):
            if print_messages:
                self.stdout.write('\r\x1b[K {0} / {1} verifying...'.format(n, total))
            n += 1
            field_cryptor = FieldCryptor(instance.algorithm, instance.mode)
            try:
                stored_secret = (field_cryptor.cryptor.HASH_PREFIX +
                                                   instance.hash +
                                                   field_cryptor.cryptor.SECRET_PREFIX +
                                                   instance.secret)
                plain_text = field_cryptor.decrypt(stored_secret)
                plain_text_encrypt_decrypt = field_cryptor.decrypt(field_cryptor.encrypt(plain_text))
                if plain_text != plain_text_encrypt_decrypt:
                    self.stdout.write('pk=\'{0}\' failed on secrets comparison\n'.format(instance.id))
                    print plain_text + '\n\n'
                    print plain_text_encrypt_decrypt + '\n\n'
                    return
                test_hash = field_cryptor.get_hash(plain_text)
                if test_hash != instance.hash:
                    failed_hash += 1
                    if print_messages:
                        self.stdout.write('pk=\'{0}\' failed on hash comparison\n'.format(instance.id))
                else:
                    verified += 1
            except:
                if print_messages:
                    self.stdout.write('pk=\'{0}\' failed on decrypt\n'.format(instance.id))
                else:
                    print 'pk=\'{0}\' failed on decrypt\n'.format(instance.id)
                failed_decrypt += 1
            del field_cryptor
            if print_messages:
                self.stdout.flush()
        msg = ('Total secrets: {0}\nVerified: {1}\nFailed decrypt: {2}\nFailed hash comparison: '
               ' {3}\nDone.').format(n, verified, failed_decrypt, failed_hash)
        if print_messages:
            self.stdout.write(msg)
        else:
            print msg

    def describe(self):
        model_cryptor = ModelCryptor()
        counts = self._list_encrypted_models(count_only=True)
        all_encrypted_models = model_cryptor.get_all_encrypted_models()
        unencrypted_instances = 0
        for encrypted_models in all_encrypted_models.itervalues():
            for meta in encrypted_models.itervalues():
                unencrypted_values_set, field_name = model_cryptor.get_unencrypted_values_set(meta['model'])
                unencrypted_instances += unencrypted_values_set.count()
        counts.update({'unencrypted_instances': unencrypted_instances})
        hours, minutes = divmod(unencrypted_instances / 120, 60)
        counts.update({'estimated_time': '{0} hour {1} minutes.'.format(hours, minutes)})
        self.stdout.write('Models: {models}\nFields: {fields}\nTotal instance: {instances}\n'
                          'Unencrypted instances {unencrypted_instances}\n'
                          'Estimated time: {estimated_time}\n'.format(**counts))
