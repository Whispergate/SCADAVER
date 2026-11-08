# Compliance

The Whispergate organisation README lists seven rules. This page maps each one to a concrete control
in this repository, so an auditor (or a future maintainer) can check behaviour instead of trusting
memory.

The parts a machine can verify are enforced by `scripts/check-compliance.sh`, which runs in CI on
every push and pull request. The rest are review rules, and are listed as such.

## Rule by rule

**1. No destructive tooling. Emulation for detection engineering is fine, intent matters.**
Control: write and control verbs stay explicit, documented and warned about in the help text
(`README.md:494`, `docs/safe-mode.md`), and the project has no payload, wiper or propagation
feature. Enforcement: review. A pull request that adds equipment-destroying behaviour is rejected on
scope, not on style.

**2. Export and sanctions compliance.**
Control: PolyForm Noncommercial licence (`LICENSE`), no redistribution path in the tree, and the
organisation handles counterparty screening. Enforcement: review at the organisation level.

**3. Data handling: client data, credentials, PII are encrypted, reported, deleted per engagement.**
Control: fixtures come from the simulators in `sim/` or documentation addresses. The compliance
script scans tracked files for credential patterns. Enforcement: automated for credentials,
review for captures.

**4. Repositories must include a usage disclaimer.**
Control: `README.md` carries `## Responsible Use and License` with the authorised-use boundary and a
pointer to `SECURITY.md`. Enforcement: automated (section presence and the permission sentence).

**5. Vulnerability disclosure: contact the vendor, 90 days, discuss before publishing.**
Control: `SECURITY.md` states the reporting channel, the 5/30/90 day timeline, safe harbour, and the
no-public-details-before-fix rule. Enforcement: automated (the 90 day window and the contact address
must be present).

**6. AI-assisted code is fine, and you own the output. No client data into public AI services.**
Control: `CONTRIBUTING.md` requires disclosure of the assist, a human who can explain every line,
and a hard no on client data, credentials and captures. Enforcement: review; the disclosure line is
a pull request checklist item.

**7. Credit your sources.**
Control: `docs/references/awesome-ics-writeups.json` keeps the research corpus in the tree, the
README keeps a `## Credits` section, and forked code keeps its attribution. Enforcement: automated
for the file and section, review for per-change citation.

## Running the check

```sh
scripts/check-compliance.sh
```

Every line is `ok` or `FAIL` with the reason. Exit status is 0 only when all checks pass. The same
script runs in `.github/workflows/compliance.yml`, so a pull request that deletes `SECURITY.md`, drops
the disclaimer, removes the credits file, or adds a silent `#[ignore]` fails before review.

On Windows the script needs a POSIX shell:

```powershell
& "C:\Program Files\Git\bin\bash.exe" scripts/check-compliance.sh
```
