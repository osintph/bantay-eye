"""Bantay-Eye: defensive internet exposure survey utility.

Part of the OSINT-PH tool suite. See https://github.com/osintph/bantay-eye
for documentation and the methodology this implements.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("bantay-eye")
except PackageNotFoundError:  # editable install before metadata exists
    __version__ = "0.1.0"

__all__ = ["__version__"]
