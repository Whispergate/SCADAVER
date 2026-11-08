# Safe mode

A plant PLC is not a lab simulator. Safe mode is the mode you run when the target is
equipment someone depends on, or when you do not yet know which target is equipment.
It trades speed for three guarantees, and it never pretends to guarantee anything else.

```sh
scadaver --safe-mode scan -i 10.0.0.0/24
```

`--safe-mode` is a global flag, so it applies to the subcommand you give it. At startup
the process prints one line so you can confirm the config it actually loaded:

```
safe mode: 250 ms between probes, 3 fragile host(s) listed
```

## The three guarantees

### 1. A delay before every probe

Safe mode inserts a fixed pause before each probe, `DEFAULT_INTERVAL`, currently 250 ms.
That is slow enough that a controller's comms task is not hammered by a sweep and fast
enough that a /24 is still usable (roughly one minute of spacing for 256 hosts on one
protocol).

The sleep is synchronous, on the caller's thread. It is deliberately not a background
timer: a timer would let a caller queue more probes while it waits, which is the exact
behaviour the delay exists to prevent.

### 2. Refusal of verbs that change state or credentials

A verb whose name looks like it writes to, logs in to, flashes, resets or otherwise
changes a device is refused while safe mode is on:

```
safe mode: refusing `Set`, which changes device state or credentials. Leave safe mode off for lab work against simulators.
```

The classification is a case-insensitive substring match against a fixed marker list
(write, set, control, exploit, hijack, fuzz, flash, reboot, stop, start, upload,
download, delete, shell, login, creds, auth, reset, restore, install, push). It is coarse
on purpose: refusing a read-only verb with an odd name costs an operator one flag, while
missing a write costs a device.

In the CLI the check runs once, at process start, against the verb you typed. A refusal
exits with status 2 before any network activity happens, so a refused command cannot have
touched a device on the way out.

### 3. Refusal of hosts on the fragile list

Any host you list as fragile is never probed, on any protocol, from any surface that goes
through the ops layer. The refusal names the host and the protocol:

```
safe mode: 10.0.0.5 is on the fragile-hosts list, refusing to probe it with Siemens
```

The fragile check runs before the delay, so a refused host does not consume a probe slot
and does not slow the sweep down.

## The fragile-hosts file

The list is read once at startup, from:

| Platform | Path |
| --- | --- |
| Linux, macOS, BSD | `$HOME/.config/scadaver/fragile_hosts.txt` |
| Windows | `%USERPROFILE%\.config\scadaver\fragile_hosts.txt` |

If `$HOME` (or `%USERPROFILE%`) is unset the path is relative to the working directory.
If the file does not exist the list is empty, which is not an error.

One address per line. `#` starts a comment, either on its own line or after an entry.
Blank lines and surrounding whitespace are ignored.

```text
# Do not touch. These are in production.

10.0.0.5
10.0.0.6
10.0.0.7   # old S7-300, comms task drops under load
#10.0.0.8  # kept for when the line is back
```

Rules worth knowing:

- Matching is an exact string comparison against the address you passed on the command
  line. There is no CIDR support and no name resolution. Listing `10.0.0.5` does not
  cover `10.0.0.0/24`, `10.0.0.05`, or a hostname that resolves to it. To protect a subnet,
  list every address in it, or do not scan that subnet.
- A line that is not a valid address is kept as written rather than dropped, so a typo
  shows up as an entry that never matches. It still counts in the startup banner, which
  counts entries, not validated addresses.
- Editing the file has no effect on a running process. Restart with `--safe-mode` to pick
  up changes.

## Limitations

These are real, and you should plan around them rather than assume safe mode covers them.

- **The verb gate runs once, at process start.** `src/main.rs` checks the top-level verb
  when the process launches and exits before scanning if it is refused. Anything that
  decides to mutate later, inside a running process, is not re-checked. The gate is a
  guard against typing the wrong subcommand, not a sandbox around the process.
- **The web surface is not gated yet.** `src/web/routes.rs` still calls the protocol
  library directly instead of going through `ops`, so `/api/scan/ip` is neither delayed
  nor subject to the fragile list. The gate moves under the web surface when the web
  migration onto the typed ops entry points lands. Until then, do not point the web UI at
  equipment you care about, and prefer the CLI or TUI in safe mode.
- **The delay is per probe, not per host.** Each protocol/host pair pays the interval. A
  host scanned with six protocols waits six intervals, and a retry is another interval.
  This is intentional (the device sees six conversations, so it gets six pauses) but it
  means the wall-clock cost scales with protocols times hosts, not hosts.
- **The verb list is heuristic.** Marker matching refuses names that are harmless in
  context (a read-only verb called `GetSetpoint` would be refused because its name
  contains `set`, and `Restore` is refused even when a surface only prints a saved config)
  and would miss a mutating verb whose name contains none of the markers. It is a coarse
  gate, not a proof.
- **Safe mode does not know what a device is.** It cannot tell a simulator from a live PLC,
  and it does not stop you from running an exploit binary, a shell, or a protocol client
  outside this tool. It only slows and refuses the probes and verbs this process issues.
- **There is no per-host budget.** Safe mode spaces probes apart; it does not cap how many
  a host receives over a session, and it does not add jitter.

## What to use instead in a lab

Leave safe mode off when the target is a simulator or a range you own. The delay makes a
sweep take minutes instead of seconds, and the verb gate blocks exactly the write paths
you are testing. Against `sim/` the two modes should produce the same findings, only
slower, which is what the `tests/safety.rs` suite checks at the library boundary.
