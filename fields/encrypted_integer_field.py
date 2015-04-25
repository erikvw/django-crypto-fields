from .local_rsa_encryption_field import LocalRsaEncryptionField


class EncryptedIntegerField(LocalRsaEncryptionField):

    description = "local-rsa encrypted field for 'IntegerField'"

    def to_python(self, value):
        """ Returns as integer """
        retval = super(EncryptedIntegerField, self).to_python(value)
        retval = int(retval)
        return retval
