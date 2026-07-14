#!/usr/bin/env bash
# Build the gate and check all six scenarios produce the expected verdict/exit.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -p assayist-gate
G=./target/release/assayist-gate
D=$(mktemp -d)
python3 scripts/gen_testdata.py "$D"
A=$(for i in $(seq 0 9); do echo -n " $D/a$i.json"; done)
mk(){ for i in $(seq 0 9); do echo -n " $D/$1$i.json"; done; }
DB=$(for i in $(seq 0 9); do echo -n " $D/dbase$i.json"; done)
DC=$(for i in $(seq 0 5); do echo -n " $D/dcand$i.json"; done)
verdict(){ python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['outcome']['verdict'])" "$1"; }
check(){ # name expected_verdict expected_exit cmd...
  local name="$1" ev="$2" ex="$3"; shift 3
  set +e; "$@" --out "$D/o.json" >/dev/null 2>"$D/e.txt"; local code=$?; set -e
  local v="error"; [ -f "$D/o.json" ] && v=$(verdict "$D/o.json") || true
  if [ "$code" = "$ex" ]; then local ok="OK"; else local ok="MISMATCH"; fi
  printf '%-42s exit=%s (want %s) verdict=%-13s %s\n' "$name" "$code" "$ex" "$v" "$ok"
  rm -f "$D/o.json"
}
check "1 ab regression"        fail 2 $G --mode ab_permutation --a $A --b $(mk breg)
check "2 ab no-change"         pass 0 $G --mode ab_permutation --a $A --b $(mk bsame)
check "3 ab contaminated"      contaminated 3 $G --mode ab_permutation --a $A --b $(mk bcont)
check "4 ab tenancy mismatch"  error 1 $G --mode ab_permutation --a $A --b $D/btenancy.json $D/bsame0.json
check "5 drift"                fail 2 $G --mode longitudinal_drift --baseline $DB --candidate $DC
check "6 triad"                fail 2 $G --mode subsystem_triad --a $A --b $(mk breg)
rm -rf "$D"
