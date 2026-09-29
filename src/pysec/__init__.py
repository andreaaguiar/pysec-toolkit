"""PySec Toolkit - security assessment tools."""
from importlib.resources import files

__version__ = "0.1.0"


def data_path(name):
    """Return the filesystem path to a bundled data file (wordlist or password list)."""
    return str(files("pysec.data") / name)
