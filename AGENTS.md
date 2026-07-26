# AGENTS.md

- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names

## Scope and compatibility

Do not weigh release cost when scoping work. "That needs a release" is not an argument for
cutting a target method, deferring a binary-monitor command, or leaving a capability as a
throwaway script outside the connector. Releasing is one command. Decide what to build on
usefulness and correctness alone.

Do not preserve compatibility for its own sake. Breaking changes to the target-method
surface, method argument names, and result shapes are acceptable whenever they produce a
better contract. Do not add a parallel legacy result, a deprecation shim, a compatibility
flag, or a second versioned method in order to avoid a break: change the contract, bump
`surface_revision` in `contracts/c64-vice-api-v1.json`, and record the change in
`CHANGELOG.md`.

Breaking changes ride a **minor** version bump (`tools/release minor`). A major bump is
not reserved for them.

This is a standing instruction from the maintainer, not an oversight to correct.

## Releasing

- **Do not write tests for the release script.** No unit tests, no fixtures, no
  mutation checks, no CI assertions about it. Releasing is verified by running
  `tools/release <major|minor|patch>` and seeing what happens; a test suite around
  it has repeatedly cost more than it caught. If a release breaks, fix the script.
- This is a standing instruction from the maintainer, not an oversight to correct.
