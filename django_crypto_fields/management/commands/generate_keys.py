import sys

from django.conf import settings
from django.core.management.color import color_style
from django.core.management.base import BaseCommand, CommandError

from django_crypto_fields.key_path import default_key_path
from ...keys import Keys
from django_crypto_fields.key_creator import KeyCreator


class Command(BaseCommand):
    help = 'Generate RSA asymmetric keys, AES symmetric keys and a salt.'

    def add_arguments(self, parser):
        # parser.add_argument('keypath', nargs=1, type=str)
        style = color_style
        try:
            default_path = settings.KEY_PATH
        except AttributeError:
            default_path = default_key_path
            sys.stdout(style.INFO(
                f'setting.KEY_PATH not found. Using path=\'{default_path}\''))
        try:
            default_prefix = settings.KEY_PREFIX
        except AttributeError:
            default_prefix = 'user'
            sys.stdout(style.INFO(
                f'setting.KEY_PREFIX not found. Using prefix=\'{default_prefix}\''))

        parser.add_argument(
            '--keypath',
            action='store',
            dest='keypath',
            default=default_path,
            help=f'Set key path to something other than the \'{default_path}\'')
        parser.add_argument(
            '--keyprefix',
            action='store',
            dest='keyprefix',
            default=default_prefix,
            help=f'Set key prefix to something other than \'{default_prefix}\'')

    def handle(self, *args, **options):
        key_creator = KeyCreator
        try:
            Keys.create_keys(
                prefix=options['keyprefix'], path=options['keypath'])
        except (FileNotFoundError, FileExistsError, OSError) as e:
            raise CommandError(e)
