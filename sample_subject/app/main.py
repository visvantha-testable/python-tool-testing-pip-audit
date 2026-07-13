"""Minimal sample app for pip-audit training subject."""

import platformdirs
from packaging.version import Version
import typing_extensions


def health_check() -> dict[str, str]:
    return {
        "platformdirs": platformdirs.__version__,
        "packaging": Version("1.0.0").public,
        "typing_extensions": typing_extensions.__version__,
    }
