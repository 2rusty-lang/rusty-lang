# rusty RFCs

Most changes land as normal commits/PRs, no process needed. An RFC is for a
change substantial enough to want written-down agreement before code is
written: a new crate boundary, a public API shape other crates will build
on, a dependency or workspace-structure change, anything hard to reverse
once merged.

Mirrors the [rust-lang RFC process](https://github.com/rust-lang/rfcs) at
a scale that fits this repo: same section structure (Summary, Motivation,
Guide-level and Reference-level explanation, Drawbacks, Rationale and
alternatives, Prior art, Unresolved questions, Future possibilities), no
separate governance/voting machinery.

## Process

1. Copy `0000-template.md` to `NNNN-short-title.md`, using the next
   unused RFC number (check the highest existing file in this directory).
2. Fill it in. An RFC with no content under Drawbacks or Alternatives
   is one that wasn't actually examined — see the template.
3. Open it for review (however this repo is doing review at the time —
   a PR, a shared doc, whatever). Discussion happens on the RFC itself.
4. Once there's agreement, the RFC's status changes from `proposed` to
   `accepted` and implementation can start. If it's rejected or
   superseded, the status changes accordingly rather than deleting the
   file — a rejected RFC with its reasoning intact is worth more than an
   empty history.

An accepted RFC that turns into a single, self-contained implementation
decision may also want an ADR (`docs/adr/ADR-TEMPLATE.md`) capturing the
final as-built decision — the RFC is the proposal and discussion, the ADR
is the terse, permanent record of what was actually decided.
