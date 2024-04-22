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

## Side Notes & Limitations

- Backend uses Trellix TQL
- Pipeline uses Trellix Helix field names
- Pipeline supports `windows` product types other will be supported
- Pipeline supports the following category types
  - process_creation
  - file
  - file_event
  - powershell
  - registry
  - dns_query
  - network_connection
- Any unsupported fields or categories will throw errors
