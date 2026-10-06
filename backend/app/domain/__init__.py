"""Domain model: the provider-neutral language of the assessment engine.

Nothing in this package talks to a cloud, a database or the network. Collectors
(later milestones) translate cloud API responses INTO these models; the rule engine,
reports and dashboard read FROM them.
"""
