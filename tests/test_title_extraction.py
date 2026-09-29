import pytest

from pysec import directory_enumeration, subdomain_enumeration

MODULES = [directory_enumeration, subdomain_enumeration]


@pytest.mark.parametrize("module", MODULES)
def test_extract_title_strips_whitespace(module):
    html = "<html><head><title>  Admin Panel  </title></head></html>"
    assert module.extract_title(html) == "Admin Panel"


@pytest.mark.parametrize("module", MODULES)
def test_extract_title_missing(module):
    html = "<html><head></head><body>no title here</body></html>"
    assert module.extract_title(html) is None


@pytest.mark.parametrize("module", MODULES)
def test_extract_title_empty(module):
    html = "<html><head><title></title></head></html>"
    assert module.extract_title(html) is None
