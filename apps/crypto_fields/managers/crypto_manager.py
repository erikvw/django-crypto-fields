from django.db import models


class CryptoQuerySet(models.query.QuerySet):

    def _filter_or_exclude(self, negate, *args, **kwargs):

        cust_lookups = filter(lambda s: s[0].endswith('__isencrypted'), kwargs.items())
        for lookup in cust_lookups:
            kwargs.pop(lookup[0])
            lookup_prefix = lookup[0].rsplit('__', 1)[0]
            kwargs.update({lookup_prefix + '__startswith': lookup[1]})
        return super(CryptoQuerySet, self)._filter_or_exclude(negate, *args, **kwargs)


class CryptoManager(models.Manager):

    def get_query_set(self):
        return CryptoQuerySet(self.model)

    def get_by_natural_key(self, hash_value, algorithm, mode):
        return self.get(hash=hash_value, algorithm=algorithm, mode=mode)
