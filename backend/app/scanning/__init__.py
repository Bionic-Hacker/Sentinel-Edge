"""Security scanning (Phase 8): one finding format for every scanner, and the pipeline gate.

This package is deliberately standard-library only. The gate runs in CI and from `make scan`
without the API's dependencies or a database, and Phase 8's vulnerability management imports
the same normalised findings into PostgreSQL.
"""
