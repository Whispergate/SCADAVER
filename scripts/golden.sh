#!/usr/bin/env bash
# Replays fixed CLI commands and diffs the output against captured fixtures.
#
#   scripts/golden.sh nosim            # simulators must be DOWN
#   scripts/golden.sh sim              # simulators must be UP
#   scripts/golden.sh sim --update     # re-capture (only when the change is intended)
#
# A missing fixture is a hard failure (exit 2). The earlier version wrote the fixture on
# first run and still printed "golden ok", so a tree with no fixtures compared nothing
# against nothing and reported success.
set -euo pipefail

mode=${1:-}
update=${2:-}
case "$mode" in
  nosim) cases=tests/golden/cases-nosim.txt ;;
  sim)   cases=tests/golden/cases-sim.txt ;;
  *)
    echo "usage: $0 nosim|sim [--update]" >&2
    exit 2
    ;;
esac

dir="tests/golden/$mode"
mkdir -p "$dir"
drift=0
missing=0
ran=0

# The case files are checked out with CRLF on Windows (core.autocrlf=true), so the last
# argument of every line arrives as "scan\r". clap then answers with a usage error and a
# healthy tree reads as fixture drift. Strip CR once here, before the name/args split, so
# both modes see the same line.
cr=$(printf '\r')

while IFS= read -r line; do
  line=${line%"$cr"}
  case "$line" in '' | \#*) continue ;; esac
  name=$(printf '%s' "$line" | sed -n 's/^\[\([A-Za-z0-9_-]*\)\].*/\1/p')
  args=$(printf '%s' "$line" | sed -n 's/^\[[A-Za-z0-9_-]*\][[:space:]]*//p')
  if [ -z "$name" ]; then
    echo "case has no [name] prefix: $line" >&2
    drift=1
    continue
  fi
  file="$dir/$name.txt"
  # shellcheck disable=SC2086
  out=$(cargo run --quiet -- $args --color never 2>&1 || true)
  # core.autocrlf also leaves CRLF in the fixtures while the binary writes bare LF; strip
  # CRs from the captured text as well, so the diff reports content and not line endings.
  out=${out//"$cr"/}
  ran=$((ran + 1))
  if [ "$update" = "--update" ]; then
    printf '%s\n' "$out" >"$file"
    echo "wrote $file"
  elif [ ! -f "$file" ]; then
    echo "MISSING fixture $file" >&2
    echo "  capture it with '$0 $mode --update' and the simulators in the right state" >&2
    missing=1
  elif ! diff -u <(tr -d "$cr" <"$file") <(printf '%s\n' "$out"); then
    echo "DRIFT in $name" >&2
    drift=1
  fi
done <"$cases"

if [ "$ran" -eq 0 ]; then
  echo "no cases ran in $cases" >&2
  exit 2
fi
if [ "$missing" -ne 0 ]; then
  exit 2
fi
if [ "$drift" -eq 0 ]; then
  echo "golden ok ($mode, $ran cases)"
fi
exit "$drift"
