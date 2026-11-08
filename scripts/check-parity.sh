#!/usr/bin/env bash
# Fails when a surface talks to casket directly instead of going through ops.
#
# The rule this enforces: a protocol fix lands in src/ops/ and all three interfaces
# get it. A surface that reaches past ops is the reason the v1.7.2 Modbus fix had to
# be applied four times (see CHANGELOG.md).
#
# grep, not ripgrep: rg is not installed on every dev box or runner.
set -euo pipefail
surfaces=(src/cli.rs src/tui.rs src/web/routes.rs)
status=0
for f in "${surfaces[@]}"; do
  if [ -f "$f" ]; then
    hits=$(grep -c 'casket::' "$f" || true)
    if [ "${hits:-0}" -gt 0 ]; then
      echo "FAIL $f calls casket:: $hits times; move it into src/ops/" >&2
      { grep -n 'casket::' "$f" | head -5 >&2; } || true
      status=1
    fi
  fi
done
if [ "$status" -eq 0 ]; then
  echo "ok: every surface goes through ops"
fi
exit $status
