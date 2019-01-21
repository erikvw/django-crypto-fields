import re

from django.forms import ValidationError

from .base_rsa_field import BaseRsaField


class FirstnameField(BaseRsaField):

    """ Restricted-rsa encrypted field for a model's Firstname
    attribute.
    """

    def validate_with_cleaned_data(self, attname, cleaned_data):
        if attname in cleaned_data:
            first_name = cleaned_data.get(attname, None)
            if (
                first_name
                and "last_name" in cleaned_data
                and "initials" in cleaned_data
            ):
                # check if value is encrypted, if so we need to decrypt it to
                # run the tests
                if self.is_encrypted(first_name):
                    self.decrypt(first_name)
                if not self.is_encrypted(first_name):
                    initials = cleaned_data.get("initials", None)
                    last_name = cleaned_data.get("last_name", None)
                    if not re.match(r"^[A-Z]{2,3}$", initials):
                        raise ValidationError(
                            "Ensure initials are letters (A-Z) in upper case, "
                            "no spaces or numbers."
                        )
                    # check first and last initial matches first and last name
                    if initials and first_name:
                        if first_name[:1].upper() != initials[:1].upper():
                            raise ValidationError(
                                "First initial does not match first name, "
                                "expected '{}' but you wrote '{}'.".format(
                                    first_name[:1], initials[:1]
                                )
                            )
                    if initials and last_name:
                        if last_name[:1].upper() != initials[-1:].upper():
                            raise ValidationError(
                                "Last initial does not match last name, "
                                "expected '{}' but you wrote '{}'.".format(
                                    last_name[:1], initials[-1:]
                                )
                            )
