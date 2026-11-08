# Security Policy

This policy covers the SCADAver source tree: the CLI, TUI and web surfaces, the protocol
implementations under `src/ops/`, the simulators under `sim/`, and the crate published to crates.io
as `scadaver`.

## In scope

- Memory safety, panics and logic errors reachable from a crafted response, a malformed packet, or a
  hostile endpoint.
- Authentication, authorisation or injection defects in the web surface (`src/web/`).
- Secrets, credentials or client data committed to the tree, or written to disk in cleartext where
  the documentation promises otherwise.
- Supply chain: a dependency, build script or CI workflow that can execute unintended code.

## Out of scope

- Vulnerabilities in third-party devices, firmware or vendor software that SCADAver talks to. Report
  those to the vendor; we will happily coordinate timing with you.
- Misconfiguration of your own deployment: an exposed web UI, default credentials, a lab host left
  reachable.
- Damage caused by the documented write and control verbs (`set`, `run`). Those change controller
  state on purpose and warn about it inline; using them against production is out of scope.
- Denial of service caused by scanning equipment that cannot handle the traffic. SCADAver sends
  protocol traffic by design.

## Reporting

Report privately. Do not open a public issue, and do not publish a proof of concept first.

- Email `contact@whispergate.org` with `SCADAver security` in the subject, or
- use GitHub's private vulnerability reporting on the repository (Security tab, "Report a
  vulnerability").

Include the version (`scadaver --version`), the surface (CLI, TUI, web), the protocol, the smallest
reproduction you have, and the impact you believe it has. A crashing input plus the exact command
that reaches it is worth more than a writeup.

## What happens next

Coordinated disclosure, 90 days:

- Within 5 working days: acknowledgement and a tracking reference.
- Within 30 days: initial assessment, severity, and a fix plan or a reasoned rejection.
- Within 90 days: fix released, or an extension agreed with you in writing before the deadline.
- You are credited in the release notes unless you ask not to be.
- No public details before the fix ships or the 90 days elapse, whichever comes first. If the defect
  is being exploited in the wild, tell us and the window shortens for everyone.

## Safe harbour

Research against systems you own, or have explicit written permission to test, is authorised under
this policy and in line with the project licence. We will not pursue legal action for good-faith
research that follows this document, stays inside your own scope, does not touch third-party data,
and does not put real equipment or people at risk. Keep write and control testing to the simulators
in `sim/` or to a lab you control.

## AI-assisted reports

Welcome, under the same rule as contributions: you are responsible for the output. Verify the claim
against the source or a real target before sending it, and do not paste client data, credentials or
captured traffic belonging to someone else into a public model.
