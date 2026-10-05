"""Trustworthy Data Space Framework.

A research prototype of a sovereign data space: participants keep their data
in their own connector, publish offers in a shared catalog, and govern their
use through machine-readable policies that are enforced and audited.
"""

from dataspace.space import DataSpace

__version__ = "0.1.0"
__all__ = ["DataSpace", "__version__"]
