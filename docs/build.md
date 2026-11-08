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
- `cargo clippy --all-targets -- -D warnings`: exit 0
- `cargo fmt --all -- --check`: clean
- `cargo test -- --test-threads=1`: 360 passed, 0 failed, 35 ignored
- `scripts/golden.sh nosim`: 3 cases, `golden ok`
- `scripts/golden.sh sim`: 6 cases, `golden ok`
- `scripts/check-parity.sh`: red, 109 / 53 / 142 direct `casket::` lines (see above)
- `cargo test --bin scadaver omron_web -- --ignored`: 2 passed (FINS simulator on 19600/19601)

Of those 360 runs, 46 are the same tests run twice. `src/lib.rs` exposes `model`, `ops`,
`protocol` and `safety` for the integration tests, and `src/main.rs` declares the same files again
as binary-private modules, so the lib test binary and the bin test binary both run them and the
tree compiles twice. 314 unique tests. The fix is to make `main.rs` a thin `use scadaver::...`
consumer, which is a build-time win, not a correctness one.

`src/ops/mod.rs` is the other thing that grew without a boundary. The address-range maps moved
out to `src/ops/ranges.rs` on 2026-11-08 (tables, devices, parse and chunk helpers, 16 unit tests
of their own), which took `ops/mod.rs` from 3729 to 3350 lines and the suite from 310 to 342 runs
without changing one byte of output. `ops` re-exports them, so callers still say
`ops::ModbusTable` and there is still only one parser.

`core.autocrlf=true` checks the case files and the fixtures out with CRLF while the binary
writes bare LF. `scripts/golden.sh` strips CR from the case line and from both sides of the
diff; without that, every case fails as a clap "unrecognized subcommand" error on the trailing
carriage return, and every fixture diff is one long CRLF-to-LF change.

Earlier runs on the 2 GB Pi are why this page says Windows: one `cargo check --lib` took 8m 00s
there and two later attempts rebooted the machine. Superseded gate numbers belong in the commit
message, not here; this section keeps the newest run only.
