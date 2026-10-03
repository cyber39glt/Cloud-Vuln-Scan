# 0008. Framework mapping: CIS, NIST CSF 2.0, SOC 2

- **Status:** Accepted
- **Date:** 2026-10-03

## Decision

- Each rule references controls in **CIS** (AWS / Azure Foundations Benchmarks),
  **NIST CSF 2.0** and **SOC 2** (Trust Services Criteria). One finding, many
  references; no per-framework engines.
- Mappings live in data files, separate from rule logic, and record the framework
  version.
- **Licensing:** NIST CSF is public domain, so its text can be included. CIS
  Benchmarks and the AICPA Trust Services Criteria are copyrighted: the open-source
  repository stores only control identifiers and short titles, not their text.
- **Wording:** reports state that a finding is *relevant to* a control. The platform
  never claims an organization is "compliant". SOC 2 mappings are interpretive and
  are labelled as such.

## Consequences

- Adding a framework means adding mapping data, not code.
- Benchmark versions must be updated deliberately when CIS publishes new releases.
