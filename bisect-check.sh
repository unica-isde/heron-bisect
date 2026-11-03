#!/usr/bin/env bash
# bisect-check.sh — the predicate `git bisect run` calls at each step.
# Exit 0   => GOOD (password-reset-urgent.eml is still "phishing", score 9)
# Exit 1   => BAD  (its verdict or its score has changed)
# Exit 125 => cannot test this commit (skip)
#
# We import the engine straight from ./src (forced to the front of the
# import path, so a globally-installed heron can't shadow it) — no
# install step is needed at any commit.
set -uo pipefail

[[ -f data/samples/password-reset-urgent.eml ]] || exit 125

RESULT="$(python3 - <<'PY' 2>/dev/null
import sys
sys.path.insert(0, "src")
try:
    from heron.parser import parse_eml
    from heron.scorer import triage
except Exception:
    sys.exit(125)
raw = open("data/samples/password-reset-urgent.eml").read()
r = triage(parse_eml(raw, "password-reset-urgent.eml"))
print(r.verdict.value, r.score)
PY
)"
RC=$?
[[ $RC -eq 125 || -z "$RESULT" ]] && exit 125

echo "  password-reset-urgent.eml -> $RESULT"
[[ "$RESULT" == "phishing 9" ]] && exit 0 || exit 1
