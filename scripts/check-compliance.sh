#!/usr/bin/env bash
# Compliance gate: the organisation rules that a machine can verify.
#
# Run from anywhere; it resolves the repository root itself.
#   scripts/check-compliance.sh
#
# Exit 0 when every check passes, 1 otherwise. Each line is "ok" or "FAIL" with the reason, so the
# CI log reads as an audit rather than a diff.

set -u

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root" || exit 2

failures=0

ok() { printf 'ok    %s\n' "$1"; }
bad() {
    printf 'FAIL  %s\n' "$1"
    failures=$((failures + 1))
}

# 1. The files a reader needs to answer "what is this, may I use it, who do I tell".
for f in LICENSE README.md SECURITY.md CONTRIBUTING.md CHANGELOG.md Cargo.toml; do
    if [ -s "$f" ]; then ok "file $f"; else bad "file $f is missing or empty"; fi
done

# 2. Usage disclaimer: the authorised-use paragraph is the one the rules require.
if grep -q '^## Responsible Use and License' README.md; then
    ok "README has the responsible-use section"
else
    bad "README lacks '## Responsible Use and License'"
fi
if grep -qi 'explicit permission' README.md; then
    ok "README states the permission boundary"
else
    bad "README does not mention explicit permission"
fi

# 3. Disclosure policy: coordinated, 90 days.
if grep -q '90 days' SECURITY.md; then
    ok "SECURITY.md states the 90 day window"
else
    bad "SECURITY.md does not state a 90 day disclosure window"
fi
if grep -qi 'contact@whispergate.org' SECURITY.md; then
    ok "SECURITY.md gives a reporting channel"
else
    bad "SECURITY.md has no reporting channel"
fi

# 4. Licensing must be declared to the package manager, not only in a file.
if grep -qE '^license(-file)? *=' Cargo.toml; then
    ok "Cargo.toml declares a licence"
else
    bad "Cargo.toml declares neither license nor license-file"
fi

# 5. Credit your sources: the research corpus stays in the tree, and the README points at credits.
if [ -s docs/references/awesome-ics-writeups.json ]; then
    ok "docs/references corpus present"
else
    bad "docs/references/awesome-ics-writeups.json is missing"
fi
if grep -q '^## Credits' README.md; then
    ok "README has a credits section"
else
    bad "README lacks '## Credits'"
fi

# 6. An ignored test must say what it needs. Silent ignores are how a suite rots.
if git rev-parse --git-dir >/dev/null 2>&1; then
    ignored=$(git grep -nE '^[[:space:]]*#\[ignore' -- '*.rs')
    silent=$(printf '%s\n' "$ignored" | grep -vc '= "')
    if [ "${silent:-0}" -eq 0 ]; then
        ok "every #[ignore] carries a reason"
    else
        bad "$silent ignored test(s) without a reason string"
        printf '%s\n' "$ignored" | grep -v '= "' | sed 's/^/      /'
    fi
else
    bad "not a git repository, cannot check ignored test reasons"
fi

# 7. Credentials do not belong in the tree. Check tracked files only, so build output cannot trip it.
if git rev-parse --git-dir >/dev/null 2>&1; then
    leaks=$(git grep -nEI '(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{10,})' -- . || true)
    if [ -z "$leaks" ]; then
        ok "no credential patterns in tracked files"
    else
        bad "credential patterns in tracked files"
        printf '%s\n' "$leaks" | sed 's/^/      /'
    fi
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "compliance: ok"
    exit 0
fi
echo "compliance: $failures failure(s)"
exit 1
