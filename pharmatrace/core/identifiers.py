"""GS1-style identifiers: GTIN check digit + cryptographically random serials."""
from __future__ import annotations

import re
import secrets

_SERIAL_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I ambiguity


def gtin_check_digit(digits: str) -> int:
    if not digits.isdigit():
        raise ValueError("GTIN body must be numeric")
    total = 0
    for i, d in enumerate(reversed(digits)):
        total += int(d) * (3 if i % 2 == 0 else 1)
    return (10 - total % 10) % 10


def is_valid_gtin(gtin: str) -> bool:
    if not re.fullmatch(r"\d{8}|\d{12}|\d{13}|\d{14}", gtin or ""):
        return False
    return gtin_check_digit(gtin[:-1]) == int(gtin[-1])


def new_serial(length: int = 12) -> str:
    return "".join(secrets.choice(_SERIAL_ALPHABET) for _ in range(length))


def unit_uid(gtin: str, serial: str) -> str:
    """GS1 Digital Link style element string: (01)GTIN(21)SERIAL."""
    return f"01{gtin}21{serial}"
