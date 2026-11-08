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
`cases-nosim.txt` / `cases-sim.txt`. A missing fixture is exit 2, not a capture: the harness used
to write whatever it saw and still print `golden ok`, which made it green on a tree with no
fixtures. Re-capture only with `--update`, in the matching simulator state.

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

The Python simulators in `sim/` are the only way to exercise a protocol without real
hardware. Ports are documented in `sim/README.md`; the ones the tests use are high ports
(21502, 33001, 11202, and so on) so a lab device on 502 is never touched. Run one at a time
on a 2 GB machine, and kill it afterwards.

## Last verified

2026-11-07, Windows 10, MSVC, cargo 1.98.0, casket v0.1.1 (`04d10467`):

- `cargo check --all-targets`: clean
- `cargo clippy --all-targets -- -D warnings`: exit 0
- `cargo test -- --test-threads=1`: 275 passed, 0 failed
- `scripts/golden.sh nosim`: 3 cases, `golden ok`
- `scripts/golden.sh sim`: 6 cases, `golden ok`

The Pi could not do this: 2 GB of RAM with a full swap, rusqlite bundled. One `cargo check --lib`
finished there in 8m 00s with zero errors, and two later attempts rebooted the machine.
