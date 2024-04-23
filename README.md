![Tests](https://github.com/sawwn23/pySigma-backend-trellix-helix/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fsawwn23%2F1924fa4d1c76d11df9dca6891eb60ac8%2Fraw%2Feedd2db2f511d39e99c8e6b492043b5e6c7152e6%2FSigmaHQ-pySigma-backend-trellix-helix.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma tql Backend

This is the tql backend for pySigma. It provides the package `sigma.backends.trellix-helix` with the `tqlBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.trellix-helix`:

It supports the following output formats:

- default: plain tql queries

This backend is currently maintained by:

- [Saw Win Naung](https://github.com/sawwn23/)

## Usage example

### Sigma CLI

You can quickly convert a single rule or rules in a directory structure using Sigma CLI. You can use:
`sigma convert -t tqlBackend  -s ~/sigma/rules` where -t is the target query language and -s is the Sigma rule or rules directory you wish to convert.

### Stand-alone Script

The following example script demonstrates how you can use the Helix backend to generate TQL queries for the following Sigma rules:

```shell
python trellix_helix.py ../../sigma/rules-threat-hunting/windows/process_creation
```

```python
# demonstrates basic usage of InsightIDR backend
from sigma.collection import SigmaCollection
from sigma.backends.trellixhelix import tqlBackend

# create pipeline and backend
trellixhelix_backend = tqlBackend()

# load a ruleset
process_start_rules = [r"C:\SigmaRules\rules\windows\process_creation\proc_creation_win_webshell_detection.yml",
                       r"C:\SigmaRules\rules\windows\process_creation\proc_creation_win_cmd_delete.yml",
                       r"C:\SigmaRules\rules\windows\process_creation\proc_creation_win_susp_rundll32_activity.yml"]

process_start_rule_collection = SigmaCollection.load_ruleset(process_start_rules)

# convert the rules
for rule in process_start_rule_collection.rules:
    print(rule.title + " conversion:")
    print(trellixhelix_backend.convert_rule(rule)[0])
    print("\n")
```

## Side Notes & Limitations

- Backend uses Trellix TQL
- Pipeline uses Trellix Helix field names
- Pipeline supports `windows` product types other will be supported
- Pipeline supports the following category types
  - process_creation
  - file
  - file_event
    <!-- - powershell -->
    <!-- - registry -->
  - dns_query
  <!-- - network_connection -->
- Any unsupported fields or categories will throw errors
