from django.core.management.base import BaseCommand, CommandError
from apps.crypto_fields.classes.key_generator import KeyGenerator


class Command(BaseCommand):
    help = 'Generate RSA asymmetric keys, AES symmetric keys and a salt.'

    def add_arguments(self, parser):
        # parser.add_argument('keypath', nargs=1, type=str)
        parser.add_argument(
            '--keypath',
            action='store',
            dest='keypath',
            default='',
            help='Set key path to something other than the default')
        parser.add_argument(
            '--keyprefix',
            action='store',
            dest='keyprefix',
            default='',
            help='Set key prefix to something other than the default')

    def handle(self, *args, **options):
        try:
            KeyGenerator.create_keys(prefix=options['keyprefix'], path=options['keypath'])
        except (FileNotFoundError, FileExistsError) as e:
            raise CommandError(e)
