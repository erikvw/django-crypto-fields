from django.core.management.base import BaseCommand
from ...utils import setup_new_keys


class Command(BaseCommand):
    help = 'Generate new encryption keys.'

    def handle(self, *args, **options):
        setup_new_keys()
