#!/usr/bin/env bash
# Two real uD3TN nodes on localhost, self-auth-dtn endpoints on each, one
# scripted exchange, checked.
#
#   UD3TN_DIR=~/ud3tn ./integrations/ud3tn/run-local.sh          # mock crypto
#   UD3TN_DIR=~/ud3tn PQ=1 ./integrations/ud3tn/run-local.sh     # ML-DSA / ML-KEM
#
# Needs, once:
#   git clone https://gitlab.com/d3tn/ud3tn.git ~/ud3tn
#   cd ~/ud3tn && git submodule update --init --recursive
#   make posix && make virtualenv
#
# What it does:
#   0. checks src/ud3tn/fields.rs against the clone's aap2.proto
#   1. starts node A (dtn://a.dtn/, MTCP 4224) and node B (dtn://b.dtn/, MTCP 4225)
#   2. configures a contact A -> B with aap2-config
#   3. runs `ud3tn_node listen` on B and five sends from A (window, promotion,
#      confidentiality, a stranger, revocation)
#   4. compares the listener's summary line with the expected one
# Logs stay in $WORK (printed at the end).

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
: "${UD3TN_DIR:?set UD3TN_DIR to a built uD3TN checkout}"
UD3TN_BIN=${UD3TN_BIN:-$UD3TN_DIR/build/posix/ud3tn}
PROTO=${PROTO:-$UD3TN_DIR/components/aap2/aap2.proto}
PORT_A=${PORT_A:-4224}
PORT_B=${PORT_B:-4225}
WORK=${WORK:-$(mktemp -d /tmp/self-auth-ud3tn.XXXXXX)}
FEATURES=ud3tn
[ "${PQ:-0}" = 1 ] && FEATURES="ud3tn pq"

if [ -x "$UD3TN_DIR/.venv/bin/aap2-config" ]; then
  AAP2_CONFIG="$UD3TN_DIR/.venv/bin/aap2-config"
else
  AAP2_CONFIG=$(command -v aap2-config || true)
fi
[ -x "$UD3TN_BIN" ] || { echo "no uD3TN binary at $UD3TN_BIN (make posix)"; exit 1; }
[ -n "$AAP2_CONFIG" ] || { echo "no aap2-config (cd \$UD3TN_DIR && make virtualenv)"; exit 1; }

echo "== 0. field numbers vs $PROTO"
python3 "$here/gen_fields.py" "$PROTO" --check

echo "== build (features: $FEATURES)"
(cd "$repo" && cargo build -q --release --features "$FEATURES" --example ud3tn_node)
NODE="$repo/target/release/examples/ud3tn_node"

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

cd "$WORK"
echo "== 1. uD3TN nodes (work dir $WORK)"
"$UD3TN_BIN" --node-id dtn://a.dtn/ --aap-port 4242 --aap2-socket "$WORK/a.aap2.socket" \
  --cla "mtcp:*,$PORT_A" > a.log 2>&1 & pids+=($!)
"$UD3TN_BIN" --node-id dtn://b.dtn/ --aap-port 4243 --aap2-socket "$WORK/b.aap2.socket" \
  --cla "mtcp:*,$PORT_B" > b.log 2>&1 & pids+=($!)
for s in a b; do
  for _ in $(seq 50); do [ -S "$WORK/$s.aap2.socket" ] && break; sleep 0.1; done
  [ -S "$WORK/$s.aap2.socket" ] || { echo "node $s did not open its socket"; cat "$s.log"; exit 1; }
done

echo "== 2. contact A -> B"
"$AAP2_CONFIG" --socket "$WORK/a.aap2.socket" --schedule 1 3600 100000 \
  dtn://b.dtn/ "mtcp:localhost:$PORT_B"
sleep 2   # the contact starts 1 s after configuration

echo "== 3. exchange"
DST=dtn://b.dtn/sad
timeout 120 "$NODE" listen --socket "$WORK/b.aap2.socket" --name b --count 8 > listen.log 2>&1 &
LISTEN=$!; pids+=($LISTEN)
sleep 0.5
A=(--socket "$WORK/a.aap2.socket" --to "$DST")
# Two bundles in the window, then the bulletin: held, then promoted.
"$NODE" send "${A[@]}" --name a --count 2 --bulletins last
# Bulletin (a duplicate by now) then a confidential bundle for b.
"$NODE" send "${A[@]}" --name a --to-name b --confidential --msg "eyes only" --bulletins first
# A node nobody vouched for: binding holds, authorization does not.
"$NODE" send "${A[@]}" --name c --bulletins none --msg stranger
# Revoke a with onset 1 (long ago): nothing held stays promotable.
"$NODE" revoke "${A[@]}" --name a --effective-at 1
sleep 1
"$NODE" send "${A[@]}" --name a --bulletins none --msg "after revocation"

wait "$LISTEN" || { echo "listener failed or timed out"; cat listen.log; exit 1; }
cat listen.log

echo "== 4. check"
want="summary: bulletins=3 bundles=5 authorized=1 held=4 decrypted=1 refused=0"
got=$(grep '^summary:' listen.log || true)
if [ "$got" = "$want" ]; then
  echo "ok: $got"
else
  echo "MISMATCH"
  echo "  want: $want"
  echo "  got:  $got"
  echo "(bundles can reorder in transit; read listen.log before concluding)"
  exit 1
fi
echo "logs: $WORK"
