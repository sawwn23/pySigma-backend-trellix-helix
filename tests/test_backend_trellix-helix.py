import pytest
from sigma.collection import SigmaCollection
from sigma.backends.trellixhelix import tqlBackend

@pytest.fixture
def trellixhelix_backend():
    return tqlBackend()

def test_trellixhelix_and_expression(trellixhelix_backend : tqlBackend):
    assert trellixhelix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
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

# def test_trellixhelix_or_expression(trellixhelix_backend : tqlBackend):
#     assert trellixhelix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel1:
#                     fieldA: valueA
#                 sel2:
#                     fieldB: valueB
#                 condition: 1 of sel*
#         """)
#     ) == ['<insert expected result here>']

# def test_trellixhelix_and_or_expression(trellixhelix_backend : tqlBackend):
#     assert trellixhelix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA1
#                         - valueA2
#                     fieldB:
#                         - valueB1
#                         - valueB2
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']

# def test_trellixhelix_or_and_expression(trellixhelix_backend : tqlBackend):
#     assert trellixhelix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel1:
#                     fieldA: valueA1
#                     fieldB: valueB1
#                 sel2:
#                     fieldA: valueA2
#                     fieldB: valueB2
#                 condition: 1 of sel*
#         """)
#     ) == ['<insert expected result here>']

# def test_trellixhelix_in_expression(trellixhelix_backend : tqlBackend):
#     assert trellixhelix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA
#                         - valueB
#                         - valueC*
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']

# def test_trellixhelix_regex_query(trellixhelix_backend : tqlBackend):
#     assert trellixhelix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA|re: foo.*bar
#                     fieldB: foo
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']

# def test_trellixhelix_cidr_query(trellixhelix_backend : tqlBackend):
#     assert trellixhelix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field|cidr: 192.168.0.0/16
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']

# def test_trellixhelix_field_name_with_whitespace(trellixhelix_backend : tqlBackend):
#     assert trellixhelix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field name: value
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']



