from datetime import date, datetime
from decimal import Decimal
from typing import Any

from dateutil.parser import parse
from dateutil.tz import UTC

from django_crypto_fields.exceptions import (
    DjangoCryptoFieldsDecodingError,
    DjangoCryptoFieldsEncodingError,
)

ENCODING = "utf-8"
DATETIME_STRING = "%Y-%m-%d %H:%M:%S %z"
DATE_STRING = "%Y-%m-%d"

INVALID_DATATYPE = (
    "Value must be of type str, date or number. Got `{value}` is `{value_type}`."
)
DECODING_TARGET_TYPE_ERROR = "Decoding error. Unhandled target type. Got `{to_type}`."
DECODING_DATEFORMAT_ERROR = (
    "Decoded string value must be in ISO date or datetime format. Got `{value}`"
)
DECODING_DATE_DATATYPE_ERROR = "Value must be either a date or datetime. Got {value}."


def safe_encode(
    value: str | int | Decimal | float | date | datetime | bytes,
) -> bytes | None:
    if value is None:
        return None
    if type(value) in [str, int, Decimal, float]:
        value = str(value).encode()
    elif type(value) in [date, datetime]:
        value = safe_encode_date(value)
    else:
        raise DjangoCryptoFieldsEncodingError(
            INVALID_DATATYPE.format(value=value, value_type=type(value))
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
        raise DjangoCryptoFieldsDecodingError(
            DECODING_TARGET_TYPE_ERROR.format(to_type=to_type)
        )
    return value


def safe_decode_date(value_as_bytes: bytes) -> date | datetime:
    """Convert bytes to string and confirm date/datetime format"""
    value_as_str = value_as_bytes.decode()
    try:
        # dt = datetime.strptime(value_as_str, "%Y-%m-%d %H:%M:%S %z")
        dt = parse(value_as_str)
    except ValueError:
        try:
            # dt = datetime.strptime(value_as_str, "%Y-%m-%d")
            dt = parse(value_as_str).replace(tzinfo=UTC)
        except ValueError as e:
            raise DjangoCryptoFieldsDecodingError(
                DECODING_DATEFORMAT_ERROR.format(value=value_as_str)
            ) from e
    return dt


def safe_encode_date(value: date | datetime) -> bytes:
    """Convert date to string and encode."""
    if type(value) is datetime:
        value = datetime.strftime(value, DATETIME_STRING)
    elif type(value) is date:
        value = datetime.strftime(value, DATE_STRING)
    else:
        raise DjangoCryptoFieldsEncodingError(DECODING_DATE_DATATYPE_ERROR.format(value=value))
    return value.encode()
