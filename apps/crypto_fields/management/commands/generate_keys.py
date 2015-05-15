from django.core.management.base import BaseCommand
from apps.crypto_fields.utils import generate_keys


class Command(BaseCommand):
    help = 'Generate new encryption keys.'

    def handle(self, *args, **options):
        generate_keys()
