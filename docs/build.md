# Building and testing SCADAVER

## The dependency is pinned to a tag

`Cargo.toml` pins the ICS protocol library to a git tag, never a branch:

```toml
casket = { git = "https://github.com/Whispergate/casket", tag = "v0.1.1" }
```

A version plus a `path` in `Cargo.toml` is two sources of truth, and the one CI sees is the
one that counts. That is exactly how `main` went red in August: the working tree compiled
against a local sibling while CI compiled against the published ref.

## Working on casket at the same time

Add an untracked `.cargo/config.toml` in this repo (gitignored):

```toml
[patch."https://github.com/Whispergate/casket"]
casket = { path = "../casket" }
```

The pinned tag still builds for everyone else, and `cargo build` uses the sibling on your
machine only.

## Commands

```sh
cargo check                      # fastest signal that the tree compiles
cargo test -- --test-threads=1   # unit tests plus simulator backed integration tests
cargo test --test ops_modbus     # one protocol vertical
scripts/golden.sh nosim          # simulators DOWN: no-response output must not drift
scripts/golden.sh sim            # simulators UP: discovery and interrogation must not drift
scripts/check-parity.sh          # no surface may call casket directly
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

`tests/golden/` holds one fixture per case, named by the `[name]` prefix in
`tests/golden/cases-nosim.txt` / `tests/golden/cases-sim.txt`. A missing fixture is exit 2, not a
capture: the harness used to write whatever it saw and still print `golden ok`, which made it
green on a tree with no fixtures. Re-capture only with `--update`, in the matching simulator state.

The wrong simulator state and real drift print the same way, so the harness now probes
127.0.0.1:21502, :33001 and :11202 before it runs a case and exits 2 naming the port:
`nosim needs the simulators DOWN, but 127.0.0.1:21502 is listening`, or the `sim` mirror when a
port is closed. Without that check, a leftover simulator from an earlier run reads as code drift
(a siemens simulator on 11202 answered during a `nosim` run on 2026-11-08 and the only symptom was
`DRIFT in siemens`). A `sim` run with a port closed used to fail on all six cases at once.

Clippy is not the same binary here and on CI. The crate enables the pedantic group, so a stable
toolchain bump turns new pedantic lints into CI failures that a local run on the older toolchain
cannot see: 1.99 added `assert_is_empty`, which demands `assert_eq!`/`assert_ne!` against an empty
value, or an `assert!` that carries a message (a bare boolean assertion does not print what the
collection held). This tree uses the message form, `assert!(v.is_empty(), "expected empty, got
{:?}", v)`, because the lint skips assertions with a custom message and it needs no type
annotation. Check the clippy version in the CI log before trusting a green local run.

## The parity gate is red, and the number is the backlog

`scripts/check-parity.sh` is the one documented gate that does not pass. On 2026-11-08 the
working tree calls `casket::` 109 times in `src/cli.rs`, 53 in `src/tui.rs` and 142 in
`src/web/routes.rs` (331 at `944fbb5`, 116 / 53 / 151 before the FINS vertical moved). The rule
is right and the count is the remaining work: `get`, `set` and `scan --broadcast` still drive
vendor clients from each surface instead of through `src/ops/`, so a protocol fix can still need
three edits.

The number counts lines that contain `casket::`, so a `use casket::...` import is one hit and a
call through that alias is zero. Removing six redundant imports and the calls under them moves
the number by six, but the real measure of a vertical is the calls that stopped going to the
wire directly; read the count as a trend, not an inventory.

Do not make it pass by re-exporting `casket` from `ops`, and do not loosen the grep: both turn
the gate into decoration. Move one protocol vertical at a time (typed `Outcome`, no printing in
`ops`) and let the count fall. The eWON register codec (word order, range checks, unit-id
validation, port resolution) now lives in `src/ops/ewon.rs` with unit tests, which took
`cli.rs` from 121 to 120; the four eWON get/set calls moved to 116 on 2026-11-08, because
`ops::ewon::read_register`, `read_coil`, `write_register` and `write_coil` now own the Modbus
call as well as the codec, and return typed values (`RegisterRead`, `CoilRead`) plus errors that
name the operation and the endpoint. The CLI keeps only the rendering and the cache write.

The port rule is worth spelling out, because it is the one place where the registry default is the
wrong number: `Protocol::Ewon::default_port()` is the IPCONF discovery port (1507) while registers
and coils are Modbus (502). `resolve_get_target` therefore keeps the explicit 0 for `EwonRegister`
and `EwonCoil` and lets `ops::ewon::modbus_port(0)` choose 502, unless a scan recorded a port for
those nouns. A unit test pins the pair (registry 1507, codec 502) so the two cannot be merged
again by accident.

The Omron FINS vertical moved the same way later on 2026-11-08, taking `cli.rs` from 116 to 109:
`ops::omron::{identity, read_dm_words, write_dm_words, cpu_state, set_cpu_mode}` own port
resolution (`fins_port`), the DM range check (`DmRange`, which rejects a span past DM65535 rather
than letting `start + count - 1` overflow) and the socket call. Three surface behaviours changed
on purpose: a short DM answer is now an error that says how many words came back instead of a
smaller success, a set token that is not a number is an error instead of being silently dropped,
and `set_cpu_state`'s `Ok(false)` (non-zero end code) is now an error instead of an
acknowledgement. `src/cli.rs` still prints.

The web half of the FINS vertical moved the same day, taking `routes.rs` from 151 to 142. All
six Omron action handlers (`omron/info`, `cpu_status`, `cpu_run`, `cpu_stop`, `read_dm`,
`write_dm`) and the live tag read now call `ops::omron`, so the DM range check and the short-reply
error apply to the browser exactly as they do to the CLI. Two behaviours changed on purpose
there: `read_dm` used to parse the start address and count with `unwrap_or`, so a non-numeric
start silently read DM0 and garbage in the count silently read ten words; both are now errors
naming the field. A blank field still means DM0 and ten words. The tag write used the literal port
9600 while the tag read used the saved `fins_port`, so a device found on a high
port could be read but never written. It now uses `device_fins_port`, the same as the read. The
tag pane still treats a failed read as "no tags", so a controller that answers short now shows an
empty DM row instead of a partial one; the error exists, the pane has nowhere to put it yet.

Ignored tests drift, because no gate runs them. `omron_web_actions_go_through_ops_against_the_simulator`
still expected the `DmRange` wording ("at least 1") for a zero-word read, but the route rejects the
count itself before `ops` sees it, with `Invalid DM word count: 0 (must be 1–100)`. It failed on
2026-11-08 the first time it was run with the command in Last verified, and now asserts the route's
message. That command is `--lib`, not `--bin scadaver`, because the web unit tests live in the
library after the `main.rs` split; the old form now runs zero tests and prints `ok`.

`omron/cpu_run` used to send Monitor (0x02), which is what the old `fins::set_cpu_mode(.., true)`
wrapper sends, while `scadaver set-cpu-mode run` sends Run (0x01). A browser click and a CLI
command therefore put the controller in different states. The route now sends Run (0x01) and says
so, because the route is named for the mode it sets. `src/ops/mod.rs`'s `exploit_omron_cpu_run`
still uses casket's boolean wrapper, which is Monitor, and still labels its output
"Monitor/Run"; that stays because it is an emulation primitive with its own documented meaning,
not a second spelling of the same command. The DM count is also range-checked now: asking for 500
words used to clamp to 100 and report success.

## Which Python

The tests and the goldens spawn `python` from `PATH`, so the interpreter that runs is whichever
one the shell resolves. The simulators need `pymodbus`, `asyncua`, `pysnmp` and `amqtt`
(`sim/requirements-test.txt`). Check before blaming the code:

```sh
python -c "import pymodbus, asyncua, pysnmp, amqtt; print('sim deps ok')"
```

On this machine the interpreter that has them is
`C:\Users\USER\AppData\Local\Programs\Python\Python313\python.exe`; another Python 3.14 can be
first on `PATH` and have none of them, which shows up as `simulator did not listen on
<port> within 10s` rather than an import error, because the tests discard the child's stderr.

```sh
PATH="/c/Users/USER/AppData/Local/Programs/Python/Python313:$PATH" cargo test -- --test-threads=1
```

## Simulators

`scripts/golden.sh` never starts a simulator, so the `sim` mode is only meaningful after these
three are up, and the fixtures were captured with modbus's default identity (no `--identity`):

```sh
PATH="/c/Users/USER/AppData/Local/Programs/Python/Python313:$PATH"
python sim/modbus_sim.py --host 127.0.0.1 --port 21502 &
python sim/dnp3_sim.py --host 127.0.0.1 --port 33001 &
python sim/siemens_sim.py --host 127.0.0.1 --port 11202 &
```

Run `nosim` with those ports closed. A `--identity schneider` modbus simulator answers as
`TM241CE24T/U` and the modbus cases drift while the other four pass.

The Python simulators in `sim/` are the only way to exercise a protocol without real
hardware. Ports are documented in `sim/README.md`; the ones the tests use are high ports
(21502, 33001, 11202, and so on) so a lab device on 502 is never touched. Run one at a time
on a 2 GB machine, and kill it afterwards.

## Last verified

2026-11-08, Windows 10, MSVC, cargo 1.98.0, casket v0.1.1 (`04d10467`):

- `cargo check --all-targets`: clean
- `cargo clippy --all-targets -- -D warnings`: exit 0 (clippy 0.1.98)
- `cargo fmt --all -- --check`: clean
- `cargo test -- --test-threads=1`: 315 passed, 0 failed, 35 ignored (350 discovered, so every
  test either passed or is marked `#[ignore]`; `--list` was counted to check that, because a
  result total that does not add up is how a test binary that runs nothing hides)
- `scripts/golden.sh nosim`: 3 cases, `golden ok`, with every simulator port closed
- `scripts/golden.sh sim`: 6 cases, `golden ok` (modbus 21502, dnp3 33001, siemens 11202)
- `scripts/check-parity.sh`: red, 109 / 53 / 142 direct `casket::` lines (see above)
- `cargo test --lib omron_web -- --ignored`: 2 passed (FINS simulator on 19600/19601)

`src/lib.rs` now owns every module and `src/main.rs` is a thin `use scadaver::...` consumer, so
each module compiles once and each unit test runs once. Before that split the binary declared the
same files again as private modules, so both test binaries ran them and the tree compiled twice:
46 of the 361 runs were the same test twice. The suite is 46 runs shorter (315) with the same
unique tests, and `cargo check --no-default-features --lib` still builds `model`, `ops`,
`protocol` and `safety` on their own, because the CLI surfaces sit behind the `cli` feature.

`src/ops/mod.rs` is the other thing that grew without a boundary. The address-range maps moved
out to `src/ops/ranges.rs` on 2026-11-08 (tables, devices, parse and chunk helpers, 16 unit tests
of their own), which took `ops/mod.rs` from 3729 to 3350 lines and the suite from 310 to 342 runs
without changing one byte of output. `ops` re-exports them, so callers still say
`ops::ModbusTable` and there is still only one parser.

`core.autocrlf=true` checks the case files and the fixtures out with CRLF while the binary
writes bare LF. `scripts/golden.sh` strips CR from the case line and from both sides of the
diff; without that, every case fails as a clap "unrecognized subcommand" error on the trailing
carriage return, and every fixture diff is one long CRLF-to-LF change.

The banner line carries the crate version, so `scripts/golden.sh` normalises that one token on
both sides before diffing. Without it, a version bump rewrote all nine fixtures and buried the
real drift: 1.7.2 to 1.8.0 did exactly that. The version is still covered, by
`env!("CARGO_PKG_VERSION")` in the banner and by the release workflow, which takes the changelog
body from `## [<tag without v>]`.

Cutting a release: set `version` in `Cargo.toml`, add the matching `## [x.y.z] - <date>` section
at the top of `CHANGELOG.md`, run the five gates, commit, then tag `vx.y.z` and push the branch
before the tag. The release workflow builds four binaries and publishes the crate; the publish
step needs the `CARGO_REGISTRY_TOKEN` secret, and without it the binaries still upload while the
crate does not.

Earlier runs on the 2 GB Pi are why this page says Windows: one `cargo check --lib` took 8m 00s
there and two later attempts rebooted the machine. Superseded gate numbers belong in the commit
message, not here; this section keeps the newest run only.
