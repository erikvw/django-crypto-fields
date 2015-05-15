from .rsa_field import RsaField


class EncryptedIntegerField(RsaField):

    description = "local-rsa encrypted field for 'IntegerField'"

    def to_python(self, value):
        """ Returns as integer """
        retval = super(EncryptedIntegerField, self).to_python(value)
        retval = int(retval)
        return retval
