#!/usr/bin/env bash
# Prove the Tamarin lemmas one at a time, each capped in memory and time, so
# a lemma that explodes is stopped and recorded instead of taking the VM down.
#
#   ./formal/prove-lemmas.sh                      # every lemma, every theory
#   ./formal/prove-lemmas.sh promotion trust      # only these theories
#   ONLY=no_rollback ./formal/prove-lemmas.sh     # one lemma (all its variants)
#
# Knobs (environment):
#   MEM=5G       Tamarin heap cap (GHC -M). Leave ~2 GB for Maude and the OS.
#   TIME=30m     wall-clock limit per lemma (coreutils timeout syntax)
#   THREADS=2    Tamarin worker threads (GHC -N). More threads, more memory.
#   FORCE=1      redo lemmas that already have a final result
#
# Results: formal/results/lemmas/<theory>[_<FLAG>]__<lemma>.txt, one per run,
# and formal/results/lemmas/TABLE.txt. Runs that finished (verified or
# falsified) are skipped next time, so the script resumes after a crash.
# Run it inside tmux: `tmux new -s tamarin`, detach with Ctrl-b d.

set -u
cd "$(dirname "$0")"
TAMARIN=${TAMARIN:-tamarin-prover}
MEM=${MEM:-5G}
TIME=${TIME:-30m}
THREADS=${THREADS:-2}
FORCE=${FORCE:-0}
ONLY=${ONLY:-}
out=results/lemmas
mkdir -p "$out"
table="$out/TABLE.txt"

command -v "$TAMARIN" >/dev/null || { echo "no $TAMARIN on PATH"; exit 1; }

# `timeout` puts the prover in its own process group, so Ctrl-C would reach
# only this script and leave the prover running. The prover runs in the
# background and the script waits for it (`wait` is interruptible); on
# Ctrl-C, stop that process group (timeout, Tamarin and the Maude it
# started) and nothing else on the machine.
child=""
stop_provers() {
  echo; echo "interrupted: stopping this run's tamarin-prover and maude" >&2
  if [ -n "$child" ]; then
    kill -TERM -- "-$child" 2>/dev/null || kill -TERM "$child" 2>/dev/null
    sleep 1
    kill -KILL -- "-$child" 2>/dev/null
  fi
  rm -f "$out/TABLE.txt.new"
  exit 130
}
trap stop_provers INT TERM
if [ "$(awk '/SwapTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)" = 0 ]; then
  echo "warning: no swap. The heap cap protects Tamarin's own memory, not Maude's."
  echo "         A 4 GB swapfile is cheap insurance (see formal/README.md)."
fi

# theory | -D flag (or -) | lemma | expected
JOBS='
confidentiality|-|exec_deliver_then_erase|verified
confidentiality|-|no_reveal_after_erase|verified
confidentiality|-|confidentiality|verified
confidentiality|-|forward_secrecy|verified
confidentiality|-|root_compromise_breaks_confidentiality|verified
promotion|-|exec_honest_promoted_after_revocation|verified
promotion|-|promotion_after_revocation_is_safe|verified
promotion|-|promotion_before_revocation_is_exposed|verified
promotion|CREATION_TIME|promotion_after_revocation_is_safe|falsified
trust|-|exec_authorize_via_peer|verified
trust|-|exec_withdraw_then_regrant|verified
trust|-|update_origin|verified
trust|-|grant_origin|verified
trust|-|withdraw_origin|verified
trust|-|member_origin|verified
trust|-|purge_on_withdrawal|verified
trust|-|authorization_sound|verified
trust|-|no_rollback|verified
trust|-|peer_root_compromise_authorizes_anyone|verified
trust|V08|no_rollback|falsified
keylog|-|exec_accept_after_rotation|verified
keylog|-|exec_accept_ipn|verified
keylog|-|no_takeover_without_next_key|verified
keylog|-|binding_no_splicing|verified
keylog|-|rotation_ends_exposure|verified
keylog|-|valid_ipn_from_inception|verified
keylog|-|ipn_pinned|verified
keylog|-|rx_log_monotone|verified
keylog|-|stale_log_cutoff|verified
keylog|-|first_seen_no_branch_switch|verified
keylog|-|next_key_theft_takes_over|verified
keylog|-|fork_wins_where_seen_first|verified
keylog|V08|no_takeover_without_next_key|falsified
keylog|V08|v08_operational_key_takeover|verified
'

# Result of one log: verified | falsified | incomplete | "" (none found).
outcome() {
  local line
  line=$(grep -E "^ *$2 \((all-traces|exists-trace)\): " "$1" | tail -1)
  case "$line" in
    *": verified"*) echo verified ;;
    *": falsified"*) echo falsified ;;
    *"analysis incomplete"*) echo incomplete ;;
    *) echo "" ;;
  esac
}

: > "$table.new"
printf '%-16s %-14s %-40s %-10s %-12s %8s  %s\n' theory flag lemma expected got time check \
  | tee -a "$table.new"

while IFS='|' read -r theory flag lemma expected; do
  [ -z "$theory" ] && continue
  if [ $# -gt 0 ] && ! printf '%s\n' "$@" | grep -qx "$theory"; then continue; fi
  [ -n "$ONLY" ] && [ "$ONLY" != "$lemma" ] && continue

  tag=$theory; [ "$flag" != - ] && tag="${theory}_$flag"
  log="$out/${tag}__${lemma}.txt"
  got=""; secs="-"
  if [ "$FORCE" != 1 ] && [ -f "$log" ]; then
    got=$(outcome "$log" "$lemma")
    case "$got" in verified|falsified) secs="(kept)" ;; *) got="" ;; esac
  fi

  if [ -z "$got" ]; then
    defs=(); [ "$flag" != - ] && defs=("-D=$flag")
    printf '... %-14s %-14s %-40s ' "$theory" "$flag" "$lemma" >&2
    start=$SECONDS
    {
      echo "\$ $TAMARIN ${defs[*]} --prove=$lemma $theory.spthy +RTS -N$THREADS -M$MEM -RTS"
      echo "(timeout $TIME)"
      echo
    } > "$log" 2>&1
    nice -n 10 timeout "$TIME" "$TAMARIN" "${defs[@]}" --prove="$lemma" "$theory.spthy" \
      +RTS -N"$THREADS" -M"$MEM" -RTS >> "$log" 2>&1 &
    child=$!
    wait "$child"
    echo "exit: $?" >> "$log"
    child=""
    secs=$((SECONDS - start))s
    rc=$(tail -1 "$log" | sed -n 's/^exit: //p')
    got=$(outcome "$log" "$lemma")
    if [ -z "$got" ]; then
      if [ "$rc" = 124 ]; then got=TIMEOUT
      elif grep -qiE "heap overflow|out of memory" "$log" || [ "$rc" = 251 ]; then got=OUT-OF-MEM
      else got="ERROR($rc)"; fi
    fi
    echo "$got ($secs)" >&2
  fi

  check=ok; [ "$got" != "$expected" ] && check=UNEXPECTED
  printf '%-16s %-14s %-40s %-10s %-12s %8s  %s\n' \
    "$theory" "$flag" "$lemma" "$expected" "$got" "$secs" "$check" | tee -a "$table.new"
done <<< "$JOBS"

mv "$table.new" "$table"
echo
echo "table: formal/$table"
echo "send:  tar czf tamarin.tgz formal/results/lemmas"
