# Architecture

## The shape in one paragraph

`scadaver` is four layers stacked bottom to top: `casket`, an external pinned crate that owns every
wire format; `src/ops/`, one module per protocol, which turns a request into bytes, sends them,
parses the answer and returns typed values or an error that names the operation; `src/model.rs` and
`src/protocol.rs`, the shared records and the single registry of protocol names and default ports;
and the three surfaces, `src/cli.rs`, `src/tui.rs` and `src/web/`, which parse arguments, call `ops`
and render. `src/main.rs` is 83 lines and does nothing except call into the library.

## Layers and who may call whom

- `casket` (external, tag `v0.1.1`): frame codecs and the socket calls that carry them. Nothing in
  this repo should call it except `src/ops/`.
- `src/ops/`: 18 files. Sixteen are one protocol each (`bacnet`, `beckhoff`, `dnp3`, `enip`,
  `iec104`, `mitsubishi`, `modbus`, `mqtt`, `omron`, `opcua`, `phoenix`, `rockwell`, `schneider`,
  `siemens`, `snmp`, plus the shared dispatch in `mod.rs`), and `ranges.rs` holds the Modbus and
  SLMP address tables and chunkers.
- `src/model.rs`: `EndpointRecord`, `Outcome`, `Message`, `Level`. These are what a surface prints
  and what the database layer stores.
- `src/protocol.rs`: the `Protocol` enum and `ALL`, sixteen entries. One place knows that eWON
  defaults to 1507 and Modbus to 502.
- Surfaces: `src/cli.rs` (5358 lines), `src/tui.rs` (6714), `src/web/` (`routes.rs` 5539 plus three
  static assets inlined with `include_str!`). They share the library through `src/lib.rs`, and the
  CLI-side modules sit behind a `cli` feature that is on by default.
- `src/safety.rs`: safe mode, fragile-host refusal, and the table of verbs that mutate a device.

The hard rule: a surface may not call `casket` directly. `scripts/check-parity.sh` greps each
surface for `casket::` and fails on any hit. The current counts, which are the backlog rather than
a pass, are 109 in `cli.rs`, 53 in `tui.rs`, 142 in `routes.rs`. Every one of those is a protocol
behaviour that still lives in a surface, so a fix there reaches one interface instead of three.

## Data flow for one verb

`scadaver get register --protocol ewon -i 10.0.0.5 --type int16 --address 100`

1. `src/cli.rs` parses `Verb::Get { noun: GetNoun::Register { .. } }`, resolves the target, and asks
   `src/protocol.rs` for the default port of `Protocol::Ewon`, which is 1507, the IPCONF discovery
   port.
2. The CLI passes the user's port, or 0 when the user gave none, into `src/ops/ewon.rs`.
   `ewon::modbus_port` maps 0 to 502 by delegating to `casket::core::modbus::effective_port`, so a
   tag read never inherits the discovery port. An explicit 1507 is honoured, because the user may
   really mean it.
3. `ops::ewon::read_register` validates the unit id (1 through 247), encodes the request, calls
   `casket`, and decodes the reply with `decode_register`, which reports how many words came back
   when the reply is short.
4. `outcome.record` and the formatted value go back to `cli.rs`, which prints them and writes the
   row through `src/db.rs`.

Nothing above the `ops` line knows a byte offset. Nothing below it knows about terminals or HTML.

## The four invariants

1. `ops` returns and never prints. A protocol function's return type is its contract, and the error
   variant names the operation and the value that failed.
2. One registry. `src/protocol.rs` is the only place that maps a protocol to a default port. The
   three private copies this replaced are why eWON was on 80 in the CLI and 1507 everywhere else.
3. CLI output is pinned. `tests/golden/` holds fixtures for nine cases, three in "simulators down"
   mode and six in "simulators up" mode, and `scripts/golden.sh` diffs both. The harness normalises
   the version token in the banner so a release does not rewrite every fixture.
4. No surface reaches past `ops`. `scripts/check-parity.sh` enforces it and its count is reported,
   not ignored.

## How it got here: v1.7.2 to 1.8.x

Before, there was no protocol layer at all. Each surface carried its own socket code and its own
copy of the protocol table:

| File | v1.7.2 lines | now |
| --- | --- | --- |
| `src/cli.rs` | 3405 | 5358 |
| `src/tui.rs` | 9057 | 6714 |
| `src/web/routes.rs` | 2540 | 5539 |

New files that did not exist at `v1.7.2`: `src/model.rs` (69), `src/protocol.rs` (166),
`src/safety.rs` (257), and all of `src/ops/` (18 files, of which `mod.rs` 3356, `ranges.rs` 660,
`ewon.rs` 599 and `omron.rs` 333 are the large ones; the sixteen protocol modules are mostly 35 to
97 lines).

Three things the split fixed, each of which was a user-visible defect rather than tidiness:

- The CLI had its own default-port table, so `--protocol ewon` without a port went to 80 while the
  rest of the tool said 1507.
- Web `cpu_run` sent Monitor (0x02) where the CLI sent Run (0x01), so two interfaces left the same
  controller in different states.
- Web `read_dm` clamped the requested word count to 100 and reported success, hiding a wrong read.

One thing it fixed that was not a defect in the tool: `src/main.rs` and `src/lib.rs` both declared
every module, so each module compiled twice and 46 of 361 test runs were the same test in two
binaries. `main.rs` is a consumer now, and the suite is 315 runs with the same unique tests.

## What is still wrong

- `src/ops/mod.rs` is 3356 lines and mixes the verticals with shared dispatch. The sixteen protocol
  modules are thin; the shared file is where the growth went.
- `cli.rs` grew by about 2000 lines and `routes.rs` by about 3000. The socket code left, the
  argument parsing, rendering and state did not, and the web routes in particular still carry
  handler logic that belongs in `ops`.
- The parity count is red at 109 / 53 / 142. Until it is zero, "fix it once and all surfaces get it"
  is a goal rather than a property.
- 35 tests are `#[ignore]`d. They are the ones that need a live simulator or a server, so a green
  run does not cover them.
- `scripts/sim_*.py` and `sim/*_sim.py` are two generations of simulators. They are documented in
  `sim/README.md`, not merged, because eight call sites name the exact paths.

## Where to look when you change a protocol

- Behaviour: `src/ops/<protocol>.rs`. If the change is about bytes, addresses or error text, it
  belongs there and nowhere else.
- Ports and names: `src/protocol.rs`.
- Output that must not drift: `tests/golden/` plus `scripts/golden.sh`; re-capture only with
  `--update` and only when the change is intended.
- Gates and the build environment: `docs/build.md`.
- Simulators and their provenance: `sim/README.md`.
- What a surface still does by hand: `scripts/check-parity.sh`, and the numbers it prints.
