When applying changes to this application consider the next instructions:

Rules:
  * Every change needs to consider existing tested functionality
  * New functionality need to contain tests according to the conventions
  * All tests should pass after the change
  * Documentation files need to be concise and in sync with the current implementation

Important files:

  * `docs/PROTOCOL.md`: the current specification of the messaging protocol
  * `docs/SPEC.md`: a generic text-based specification of the application
  * `docs/TESTING.md`: a document describing how to perform test driven changes to the application
  * `docs/SECURIRY.md`
  * `README.md`

Practical approach:
  * [ ] Update Gherkin features + cucumber steps
  * [ ] Update requirements.toml
  * [ ] Implement
  * [ ] Update docs: PROTOCOL.md, SPEC.md, README.md if affected (ensure the <function_name>:<line_number> references are in sync
  * [ ] Run full verification: cargo trace, cargo bdd, cargo test
