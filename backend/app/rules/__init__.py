"""Security rules and the engine that runs them.

Rules see only an `Inventory`. They must never import cloud SDKs, HTTP clients,
sockets or the database; a test enforces this (tests/test_rule_boundaries.py).
"""
