# Contributing to SCADAver

These rules come from the Whispergate organisation README, applied to this repository. They are not
aspirational: `scripts/check-compliance.sh` fails the build when the parts a machine can check are
missing.

## Before you open a pull request

Run the gates on your tree and paste the numbers into the pull request. `docs/build.md` has the
details; the short version:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test -- --test-threads=1
scripts/golden.sh nosim
scripts/check-parity.sh
scripts/check-compliance.sh
```

On Windows, shell scripts need a POSIX shell; `& "C:\Program Files\Git\bin\bash.exe" <script>`.

A change that adds or alters protocol behaviour needs a test that fails before the change and passes
after it. A test that cannot run without hardware belongs behind `#[ignore]` **with a reason naming
the missing dependency**, and it should instead be pointed at a simulator in `sim/` whenever one
exists.

## Code

- No new dependency on a raw protocol crate inside a surface (`src/cli.rs`, `src/tui.rs`,
  `src/web/routes.rs`). Those call the `ops` layer. `scripts/check-parity.sh` enforces it.
- Keep `unsafe` out of new code unless the surrounding module already establishes the invariant.
- Write and control verbs stay opt-in, documented, and loud in the help text. They are the reason
  this project exists, and the reason the disclaimer exists.
- State-changing operations get a dry-run or a confirmation path where the surface allows it.

## AI-assisted code

Allowed, and increasingly normal, under the organisation rule: **you are still responsible for the
output**.

- You must be able to explain every line in the pull request, including the ones you did not type.
- Review generated code the way you review a stranger's: for the failure mode, not the happy path.
- Disclose the assist in the pull request body in one line, for example "loader and tests drafted
  with an assistant, reviewed and exercised by me". Undisclosed assists are the ones that cost
  somebody a weekend.
- Never paste client data, credentials, captured traffic, tokens or private infrastructure detail
  into a public model. If the reproduction needs the real packet, cut it down to the fields that
  matter.
- No AI-generated bulk that nobody has read. A 900-line diff with no tests and no explanation is
  rejected on sight, whatever wrote it.

## Data handling

- Client data, credentials and PII never enter this repository, an issue, a pull request or a public
  model. Encrypt it, report it privately, delete it when the engagement ends.
- Test fixtures use documentation addresses or the simulators. Do not commit a capture from a real
  site, even anonymised.
- A secret that reaches a commit is rotated, not deleted in a follow-up commit. History keeps it.

## No destructive tooling

This is a scanner and validation framework for authorised labs. It is not a wiper and will not grow
wiper features. Emulation that proves a detection works is in scope; anything whose primary purpose
is to break equipment, corrupt a process, or spread is not.

## Export, sanctions, licensing

Do not redistribute the tooling in a way that violates EAR, ITAR or OFAC. The licence is PolyForm
Noncommercial 1.0.0 (`LICENSE`); contributions are accepted under it.

## Credit your sources

Forked code keeps its attribution. A technique taken from a blog or paper is cited in the code
comment or the pull request, with a link. The ICS research corpus that informed the protocol notes
lives in `docs/references/awesome-ics-writeups.json`.

## Security issues

Do not open a public issue for a defect in SCADAver itself. `SECURITY.md` has the reporting channel
and the 90 day coordinated disclosure window.
