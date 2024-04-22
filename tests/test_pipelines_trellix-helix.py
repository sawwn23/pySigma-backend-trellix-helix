import pytest
from sigma.collection import SigmaCollection
from sigma.backends.trellixhelix import tqlBackend

@pytest.fixture
def trellixhelix_backend():
    return tqlBackend()

def test_helix_unsupported_rule_type(trellixhelix_backend : tqlBackend):
  with pytest.raises(ValueError):
    trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_helix_unsupported_field_name(trellixhelix_backend : tqlBackend):
  with pytest.raises(ValueError):
    trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )