"""Persistence: database tables (models.py) and client-scoped access (repository.py).

Code outside this package never queries tables directly; it calls the repository,
which always requires the client whose data is being touched (ADR 0015).
"""
