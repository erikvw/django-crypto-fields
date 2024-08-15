from datetime import date, datetime
from decimal import Decimal
from typing import Any

from django_crypto_fields.exceptions import (
    DjangoCryptoFieldsDecodingError,
    DjangoCryptoFieldsEncodingError,
)

ENCODING = "utf-8"
DATETIME_STRING = "%Y-%m-%d %H:%M:%S %z"
DATE_STRING = "%Y-%m-%d"


def safe_encode(value: str | int | Decimal | float | date | datetime | bytes) -> bytes | None:
    if value is None:
        return None
    if type(value) in [str, int, Decimal, float]:
        value = str(value).encode()
    elif type(value) in [date, datetime]:
        value = safe_encode_date(value)
    else:
        raise DjangoCryptoFieldsEncodingError(
            f"Value must be of type str, date or number. Got {value} is {type(value)}"
        )
    return value


def decode_to_type(value: bytes, to_type: type) -> Any:
    if to_type in [date, datetime]:
        value = safe_decode_date(value)
    elif to_type in [Decimal]:
        value = Decimal(value.decode())
    elif to_type in [int, float]:
        value = to_type(value.decode())
    elif to_type in [str]:
        value = value.decode()
    else:
        raise DjangoCryptoFieldsDecodingError(f"Unhandled type. Got {to_type}.")
    return value


def safe_decode_date(value: bytes) -> [date, datetime]:
    """Convert bytes to string and confirm date/datetime format"""
    value = value.decode()
    try:
        value = datetime.strptime(value, "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        try:
            value = datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            raise DjangoCryptoFieldsDecodingError(
                f"Decoded string value must be in ISO date or datetime format. Got {value}"
            )
    return value


def safe_encode_date(value: [date, datetime]) -> bytes:
    """Convert date to string and encode."""
    if type(value) is datetime:
        value = datetime.strftime(value, DATETIME_STRING)
    elif type(value) is date:
        value = datetime.strftime(value, DATE_STRING)
    else:
        raise DjangoCryptoFieldsEncodingError(
            f"Value must be either a date or datetime. Got {value}."
        )
    return value.encode()
