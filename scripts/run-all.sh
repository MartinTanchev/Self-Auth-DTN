#!/usr/bin/env bash
# Run every test and experiment of self-auth-dtn, one log per step.
#
#   ./scripts/run-all.sh            # everything (~5-15 min, mostly compiling)
#   ./scripts/run-all.sh quick      # tests only
#
# Logs go to results/<timestamp>/, with SUMMARY.txt listing every step and
# its exit code. Tamarin is separate: see formal/README.md (make formal).

set -u
cd "$(dirname "$0")/.."
CARGO=${CARGO:-cargo}
out="results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"
summary="$out/SUMMARY.txt"
: > "$summary"

# run NAME CMD...  -> log to $out/NAME.txt, record exit code
run() {
  local name=$1; shift
  printf '%-34s ' "$name"
  local start=$SECONDS
  { echo "\$ $*"; echo; "$@"; } > "$out/$name.txt" 2>&1
  local rc=$?
  local t=$((SECONDS - start))
  local status=ok; [ $rc -ne 0 ] && status="FAILED (exit $rc)"
  printf '%s  %4ss\n' "$status" "$t"
  printf '%-34s %s  %ss\n' "$name" "$status" "$t" >> "$summary"
}

# --- environment -------------------------------------------------------------
{
  echo "date:   $(date -Is)"
  echo "host:   $(uname -a)"
  echo "cpus:   $(nproc)"
  free -h 2>/dev/null
  $CARGO --version; rustc --version
  grep -m1 '^version' Cargo.toml
} > "$out/00-environment.txt" 2>&1

# --- tests -------------------------------------------------------------------
run 01-tests-mock          $CARGO test --all-targets
run 02-tests-pq            $CARGO test --all-targets --features pq
run 03-tests-pq-release    $CARGO test --release --all-targets --features pq
# no_std + alloc library (std feature off): same suite, deterministic ML-DSA.
run 06-tests-nostd-mock    $CARGO test --all-targets --no-default-features --features mock
run 07-tests-nostd-pq      $CARGO test --all-targets --no-default-features --features "mock pq"
# Bare-metal build: the real proof that nothing pulls in std. Needs the target:
#   rustup target add thumbv7em-none-eabihf
if rustup target list --installed 2>/dev/null | grep -q '^thumbv7em-none-eabihf$'; then
  run 08-nostd-thumbv7em-pq  $CARGO build --lib --release --no-default-features --features pq --target thumbv7em-none-eabihf
else
  printf '%-34s %s\n' 08-nostd-thumbv7em-pq "SKIPPED (rustup target add thumbv7em-none-eabihf)" | tee -a "$summary"
fi

# uD3TN AAP 2.0 client against an in-process stand-in (no uD3TN needed).
run 09-tests-ud3tn         $CARGO test --all-targets --features ud3tn
# Against two real uD3TN nodes, when a built checkout is given.
if [ -n "${UD3TN_DIR:-}" ]; then
  run 40-ud3tn-mock          ./integrations/ud3tn/run-local.sh
  run 41-ud3tn-pq            env PQ=1 ./integrations/ud3tn/run-local.sh
else
  printf '%-34s %s\n' 40-ud3tn "SKIPPED (set UD3TN_DIR, see integrations/ud3tn/README.md)" | tee -a "$summary"
fi

if [ "${1:-}" = quick ]; then
  echo; echo "logs: $out"; exit 0
fi

# --- hygiene (informational; warnings here are not failures of the work) -----
run 04-clippy              $CARGO clippy --all-targets --features "pq ud3tn"
run 05-fmt-check           $CARGO fmt --all --check

# --- walkthrough and sizes ---------------------------------------------------
run 10-demo                $CARGO run --example demo
run 11-overhead            $CARGO run --example overhead
run 12-bench-pq            $CARGO run --release --example bench --features pq

# --- synthetic contact plans (STINT slides) ----------------------------------
run 20-coverage            $CARGO run --release --example coverage
run 21-contactplan-lunar   $CARGO run --release --example contactplan -- lunar
run 22-contactplan-mars    $CARGO run --release --example contactplan -- mars

# --- CCSDS reference scenarios ----------------------------------------------
R="$CARGO run --release --example refscenario --"
run 30-ref-default         $R
run 31-ref-lunar-blue-late $R lunar --case cross-support --late blue
run 32-ref-mars-blue-late  $R mars --case cross-support --late blue
run 33-ref-planned         $R --contacts planned
run 34-ref-peer-day-3      $R --peer-day 3
run 35-ref-peer-day-5      $R --peer-day 5
run 36-ref-peer-day-20     $R --peer-day 20
run 37-ref-sample-10min    $R --sample-min 10

# --- summary -----------------------------------------------------------------
{
  echo
  echo "test totals:"
  for f in "$out"/0[0-9]-tests-*.txt; do
    awk -v n="$(basename "$f" .txt)" '/^test result:/ {p+=$4; fl+=$6}
      END {printf "  %-24s %d passed, %d failed\n", n, p, fl}' "$f"
  done
} | tee -a "$summary"

echo
echo "logs: $out   (send the whole folder: tar czf results.tgz $out)"
