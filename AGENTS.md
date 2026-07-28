# AGENTS.md

- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names

## Agent review

- Every change except `AGENTS.md` must be reviewed with an agent skill before completion.
- Claude Code agents must use `/codex review`.
- Codex agents must use `$claude review`.

## Ghidra paths

- The Ghidra program path is available in `$GHIDRA_PROGRAM_PATH`.
- The Ghidra source path is available in `$GHIDRA_SOURCE_PATH`. Consult the source when
  it helps develop, debug, or verify Ghidra-related behavior instead of guessing about
  Ghidra internals.

## Scope and compatibility

Do not weigh release cost when scoping work. "That needs a release" is not an argument
for cutting a capability, deferring related work, or leaving it as a throwaway script
outside the maintained package. Releasing is one command. Decide what to build on
usefulness and correctness alone.

Do not preserve compatibility for its own sake. Breaking changes to public names,
argument names, group membership, and result shapes are acceptable whenever they produce
a better contract. Do not add a parallel legacy response, a deprecation shim, a
compatibility flag, or a second versioned interface in order to avoid a break: change the
contract and record it in `CHANGELOG.md`.

Breaking changes ride a **minor** version bump (`tools/release minor`). A major bump is
not reserved for them.

This is a standing instruction from the maintainer, not an oversight to correct.

## Releasing

- **Do not retain unit tests for release tooling.** The completed repository must
  contain no unit tests, fixtures, mutation checks, or CI assertions targeting it.
- **Test release-tooling changes before release.** Use temporary tests and controlled,
  non-publishing runs to exercise the affected paths, then remove all temporary test
  artifacts. Report what was tested and its result; the first real release must not
  serve as the test.
- This is a standing instruction from the maintainer, not an oversight to correct.
