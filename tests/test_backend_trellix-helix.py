import pytest
from sigma.collection import SigmaCollection
from sigma.backends.trellixhelix import tqlBackend

@pytest.fixture
def trellixhelix_backend():
    return tqlBackend()

def test_trellixhelix_and_expression(trellixhelix_backend : tqlBackend):
    assert trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: AND Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    Image: valueA
                    ParentImage: valueB
                condition: sel
        """)
    ) == ['(category : ["process create (rule: processcreate)","process creation"]) AND (metaclass:"windows" AND (process:"valueA" AND pprocess:"valueB"))']

def test_trellixhelix_or_expression(trellixhelix_backend : tqlBackend):
    assert trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: OR Test
            status: test
            logsource:
                product: windows
                category: dns_query
            detection:
                sel1:
                    Image|startswith: valueA
                sel2:
                    QueryName|endswith: valueB
                condition: 1 of sel*
        """)
    ) == ['category:"dns query (rule: dnsquery)" AND (metaclass:"windows" AND (process:"valueA*" OR query:"*valueB"))']

def test_trellixhelix_and_or_expression(trellixhelix_backend : tqlBackend):
    assert trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: AND OR Test
            status: test
            logsource:
                category: process_creation
                product: windows 
            detection:
                sel:
                    Image:
                        - valueA1
                        - valueA2
                    ParentImage:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['(category : ["process create (rule: processcreate)","process creation"]) AND (metaclass:"windows" AND ((process : ["valueA1","valueA2"]) AND (pprocess : ["valueB1","valueB2"])))']

def test_trellixhelix_or_and_expression(trellixhelix_backend : tqlBackend):
    assert trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: OR AND Test
            status: test
            logsource:
                category: process_creation 
                product: windows 
            detection:
                sel1:
                    Image: valueA1
                    ParentImage: valueB1
                sel2:
                    Image: valueA2
                    ParentImage: valueB2
                condition: 1 of sel*
        """)
    ) == ['(category : ["process create (rule: processcreate)","process creation"]) AND (metaclass:"windows" AND ((process:"valueA1" AND pprocess:"valueB1") OR (process:"valueA2" AND pprocess:"valueB2")))']

def test_trellixhelix_in_expression(trellixhelix_backend : tqlBackend):
    assert trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: IN Test
            status: test
            logsource:
                category: process_creation 
                product: windows 
            detection:
                sel:
                    Image:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['(category : ["process create (rule: processcreate)","process creation"]) AND (metaclass:"windows" AND (process : ["valueA","valueB","valueC*"]))']

def test_trellixhelix_regex_query(trellixhelix_backend : tqlBackend):
    assert trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: REGEX Test
            status: test
            logsource:
                category: process_creation 
                product: windows 
            detection:
                sel:
                    Image|re: foo.*bar
                    ParentImage: foo
                condition: sel
        """)
    ) == ['(category : ["process create (rule: processcreate)","process creation"]) AND (metaclass:"windows" AND (process:"foo.*bar" AND pprocess:"foo"))']

def test_trellixhelix_cidr_query(trellixhelix_backend : tqlBackend):
    assert trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: CIDR Test
            status: test
            logsource:
                category: dns_query
                product: windows
            detection:
                sel:
                    DestinationIp|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['category:"dns query (rule: dnsquery)" AND (metaclass:"windows" AND dstipv4:192.168.0.0/16)']

# def test_trellixhelix_field_name_with_whitespace(trellixhelix_backend : tqlBackend):
#     assert trellixhelix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: process_create 
#                 product: windows 
#             detection:
#                 sel:
#                     Parent Image: value
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']



