"""Package level tests"""
from rmcli import __version__


def test_version() -> None:
    """Make sure version matches expected"""
    assert __version__ == "0.3.0"
