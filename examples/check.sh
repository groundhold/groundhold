#!/usr/bin/env bash
# Every shipped example must still work — checked, not assumed.
#
# Why this exists: examples/acme/aws.candidate.yaml verified clean (48 satisfied,
# PROVEN) while `plan` refused it, because two implementation operands named keys
# no driver reads. It had been exported to the public repo in that state. Nothing
# caught it, because verify and plan are different gates and only verify was ever
# run on the examples. A reader following the README would have hit the wall.
#
# This runs from `make check`, so it also runs in the PUBLIC tree during the
# export's standalone gate — an example that cannot work never reaches the public
# repo again.
#
# Expectations are declared, not inferred. A REFUSED example is fine when the
# refusal is the lesson (orders-production proves an RTO claim is not executable);
# what is never fine is an outcome nobody declared.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLI="bin/groundhold-go"
VOCAB="spec/vocab"
# fixed clock: examples must not depend on the day they are checked (N1 requires
# an explicit --at, and a moving one would make failures irreproducible)
AT="2026-01-01T00:00:00Z"

pass=0
fail=0

# report <name> <expected> <got> — records the outcome, never exits early, so one
# run tells you about EVERY broken example rather than only the first.
report() {
  if [ "$2" = "$3" ]; then
    printf '  PASS %-58s %s\n' "$1" "$2"
    pass=$((pass + 1))
  else
    printf '  FAIL %-58s want=%s got=%s\n' "$1" "$2" "$3"
    fail=$((fail + 1))
  fi
}

# contracts that must load and validate on their own — DISCOVERED from the tree,
# never retyped.
#
# D692: this was a hand-written list of ten paths, and the first shipped contract
# to test it was the canary's own retirement contract — added in the same commit
# as this line, missed by the list. A scope an author has to remember to widen
# gates the author's memory, not the tree (D583). The floor keeps the discovery
# from silently finding nothing (D328).
mapfile -t CONTRACTS < <(find examples spec/examples -name '*.contract.yaml' | sort)
if [ "${#CONTRACTS[@]}" -lt 11 ]; then
  echo "found only ${#CONTRACTS[@]} shipped contracts — the scan broke, and every"
  echo "validate check below would have passed over an empty set"
  exit 1
fi
for c in "${CONTRACTS[@]}"; do
  rc=0
  "$CLI" validate "$c" >/dev/null 2>&1 || rc=$?
  report "validate $(basename "$c")" 0 "$rc"
done

# pairs: contract candidate expected-verify expected-plan
#
# 0 = proven / compiled. 2 = refused. Anything else is a crash and always a bug.
check_pair() {
  local contract="$1" candidate="$2" want_verify="$3" want_plan="$4" rc=0
  "$CLI" verify "$contract" "$candidate" --vocab "$VOCAB" >/dev/null 2>&1 || rc=$?
  report "verify $(basename "$candidate")" "$want_verify" "$rc"
  rc=0
  "$CLI" plan "$contract" "$candidate" --vocab "$VOCAB" --at "$AT" >/dev/null 2>&1 || rc=$?
  report "plan   $(basename "$candidate")" "$want_plan" "$rc"
}

check_pair examples/acme/platform.contract.yaml \
           examples/acme/aws.candidate.yaml 0 0
check_pair examples/acme/gitops-coupling.contract.yaml \
           examples/acme/gitops-coupling.aws.candidate.yaml 0 0
check_pair examples/acme/gitops-coupling.contract.yaml \
           examples/acme/gitops-coupling.gcp.candidate.yaml 0 0
check_pair examples/canary-azure/canary.contract.yaml \
           examples/canary-azure/canary.candidate.yaml 0 0
check_pair examples/laptop/laptop.contract.yaml \
           examples/laptop/laptop.candidate.yaml 0 0
# The canary's TEARDOWN pair (D692). The README tells a reader with a live Azure
# resource to run it, so it is checked like any other shipped document: the
# retired contract loads, and the candidate that no longer mentions the capability
# verifies clean. `plan` refuses with `nothing-to-change` here and that is right —
# a delete needs the binding the reader's own converge recorded, and this check has
# no ledger. The delete half of retirement is proven on `fake` by the lifecycle
# example below, which does have one.
check_pair examples/canary-azure/canary-retired.contract.yaml \
           examples/canary-azure/canary-retired.candidate.yaml 0 2
# THE THESIS, not a defect: c-rto is provable only by a restore test, so the
# candidate is not executable and plan refuses (exit 2). The README shows this
# refusal on purpose; if it ever starts compiling, the guarantee broke.
check_pair spec/examples/orders-production.contract.yaml \
           spec/examples/candidates/gcp-cloudsql.candidate.yaml 2 2
# The README's "change the intent and watch it refuse" — a database outside the
# EU under a contract that requires it inside. MUST stay violated: this example
# exists to be refused, and an EU-residency constraint that stopped biting would
# be the worst possible silent regression.
check_pair examples/lifecycle/2-refused.contract.yaml \
           examples/lifecycle/2-refused.candidate.yaml 2 2

# The README promises a full loop on the fake provider, twice, with the second run
# proving a no-op. That promise is worth exactly as much as a test of it.
LEDGER="$(mktemp -d)"
trap 'rm -rf "$LEDGER"' EXIT
rc=0
"$CLI" converge examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger "$LEDGER/try.jsonl" --provider fake --at "$AT" --yes >/dev/null 2>&1 || rc=$?
report "converge laptop (first run)" 0 "$rc"
rc=0
out="$("$CLI" converge examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger "$LEDGER/try.jsonl" --provider fake --at "$AT" --yes 2>&1)" || rc=$?
report "converge laptop (second run)" 0 "$rc"
case "$out" in
  *"already matches the candidate"*) report "converge laptop (proves no-op)" yes yes ;;
  *)                                 report "converge laptop (proves no-op)" yes no ;;
esac

# The README's create → delete lifecycle, against ONE ledger, in order. The delete
# is the interesting half: --yes must NOT be enough to destroy anything, and the
# delete target must be pinned from the recorded binding rather than guessed.
LIFE="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE"' EXIT
rc=0
"$CLI" converge examples/lifecycle/1-create.contract.yaml examples/lifecycle/1-create.candidate.yaml \
  --ledger "$LIFE/orders.jsonl" --provider fake --at "$AT" --yes >/dev/null 2>&1 || rc=$?
report "lifecycle create (2 capabilities)" 0 "$rc"
rc=0
out="$("$CLI" converge examples/lifecycle/3-retire.contract.yaml examples/lifecycle/3-retire.candidate.yaml \
  --ledger "$LIFE/orders.jsonl" --provider fake --at "$AT" --yes 2>&1)" || rc=$?
report "lifecycle delete refused without --allow-data-loss" 2 "$rc"
case "$out" in
  *consent-required*) report "lifecycle delete cites consent-required" yes yes ;;
  *)                  report "lifecycle delete cites consent-required" yes no ;;
esac
rc=0
out="$("$CLI" converge examples/lifecycle/3-retire.contract.yaml examples/lifecycle/3-retire.candidate.yaml \
  --ledger "$LIFE/orders.jsonl" --provider fake --at "$AT" --yes --allow-data-loss 2>&1)" || rc=$?
report "lifecycle delete with consent" 0 "$rc"
case "$out" in
  *"delete a-delete-assets"*target=*) report "lifecycle delete pins its target" yes yes ;;
  *)                                  report "lifecycle delete pins its target" yes no ;;
esac

# Completeness: every shipped candidate must be NAMED somewhere above (D692).
#
# Expectations stay declared — this script refuses to guess whether an example is
# meant to pass or to be refused — but WHICH examples get checked must not be a
# matter of memory. A candidate that ships and appears nowhere here is a document
# a reader can run and this suite never did.
mapfile -t CANDIDATES < <(find examples spec/examples -name '*.candidate.yaml' | sort)
if [ "${#CANDIDATES[@]}" -lt 10 ]; then
  echo "found only ${#CANDIDATES[@]} shipped candidates — the scan broke"
  exit 1
fi
for cand in "${CANDIDATES[@]}"; do
  if grep -qF -- "$cand" "$ROOT/examples/check.sh"; then
    report "covered $(basename "$cand")" yes yes
  else
    report "covered $(basename "$cand")" yes no
  fi
done

# ---------------------------------------------------------------------------
# Shipped PLAN documents. Contracts and candidates are discovered and checked
# above; plans were not, and the one this repository ships had been INVALID since
# the rule that an update carries a reviewed change-set (D46) — a month, in the
# directory an independent implementer is invited to measure against.
#
# Its header states the property this checks, and stated it falsely: "the reads
# block pins the ACTUAL hashes of the example contract and candidate in this repo
# — `groundhold hash` on those files reproduces them". Neither did. The document
# told the reader exactly how to catch it out.
mapfile -t PLANS < <(find examples spec/examples -name '*.plan.yaml' | sort)
if [ "${#PLANS[@]}" -lt 1 ]; then
  echo "found no shipped plan documents — the scan broke"
  exit 1
fi
for plan in "${PLANS[@]}"; do
  # It must LOAD. forecast is the reader's way in, and it validates the plan before
  # anything else; the candidate is the one this repository ships.
  got=0
  "$CLI" forecast "$plan" spec/examples/candidates/gcp-cloudsql.candidate.yaml \
    --at "$AT" >/dev/null 2>&1 || got=$?
  report "plan loads $(basename "$plan")" 0 "$got"

  # And the hashes it pins must be the ones `groundhold hash` produces, which is
  # what the file says about itself.
  for pair in "contractHash spec/examples/orders-production.contract.yaml" \
              "candidateHash spec/examples/candidates/gcp-cloudsql.candidate.yaml"; do
    set -- $pair
    pinned="$(grep -oE "$1: \"sha256:[0-9a-f]+\"" "$plan" | grep -oE 'sha256:[0-9a-f]+' || true)"
    actual="$("$CLI" hash "$2" 2>/dev/null | tail -1)"
    report "plan $1 reproduces" "$actual" "$pinned"
  done
done

# ---------------------------------------------------------------------------
# The NEWCOMER PATH (D1063): what someone with a downloaded binary and no clone
# does. Everything above checks files this repository SHIPS — every one of which
# exists only in a clone. The published sixty-second path starts from an empty
# directory and uses documents the tool writes about itself, and until now nothing
# walked it.
#
# D1063 is the proof that it breaks silently: the scaffold emitted an attribute no
# provider can honour, so `converge` APPLIED once and REFUSED every pass after —
# from documents the tool had just written for the reader. Found by hand; nothing
# would have found it again.
#
# It lives here rather than in a Go test because `converge` re-executes the binary
# for each phase, so it cannot be driven in-process: a test binary would spawn
# itself. This harness already has the built CLI, which is what a reader has too.
NEW="$(mktemp -d)"
trap 'rm -rf "$NEW"' EXIT
"$CLI" example contract > "$NEW/my.contract.yaml" 2>/dev/null
"$CLI" example candidate "$NEW/my.contract.yaml" > "$NEW/my.candidate.yaml" 2>/dev/null

# Exactly the blank the README tells the reader to fill — no more, no fewer. A
# second one means the published instruction is wrong and a reader lands on a
# refusal without being told which field is missing. Everything the contract PINS
# is answered by the scaffold itself (D1087), so only the provider's service token
# is left to decide.
blanks="$(grep -oE '^[[:space:]]*[A-Za-z.]+: ""' "$NEW/my.candidate.yaml" \
          | sed -E 's/^[[:space:]]*//; s/: ""//' | paste -sd, -)"
report "newcomer scaffold leaves the documented blank" "service" "$blanks"

sed -i 's|service: ""|service: "rds"|' "$NEW/my.candidate.yaml"

first="$("$CLI" converge "$NEW/my.contract.yaml" "$NEW/my.candidate.yaml" \
  --ledger "$NEW/try.jsonl" --provider fake --at "$AT" --yes 2>&1 | tail -1 || true)"
report "newcomer path: first converge applies" APPLIED "$first"

# The one that matters. A scaffold that declares what no provider can honour
# applies once and then never converges on its own output.
second="$("$CLI" converge "$NEW/my.contract.yaml" "$NEW/my.candidate.yaml" \
  --ledger "$NEW/try.jsonl" --provider fake --at "$AT" --yes 2>&1 | tail -1 || true)"
report "newcomer path: second converge is a no-op" CONVERGED "$second"

# The `adopt-candidate` skill crosses to the public tree and tells an agent to run
# `scripts/adopt-candidate.sh` as its central step. Until now only the script's REFUSAL
# path was ever executed — the D606 guard, driven with GROUNDHOLD=/bin/false precisely so
# nothing would run. The path the skill actually publishes, the one that ends in an
# adopted binding, was never executed by anything.
ADOPT="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$NEW" "$ADOPT"' EXIT
"$CLI" discover --provider fake --at "$AT" > "$ADOPT/discovery.json" 2>/dev/null || true
res="$(grep -oE '"providerId": *"[^"]+"' "$ADOPT/discovery.json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
report "discover --provider fake offers a resource to adopt" yes "$([ -n "$res" ] && echo yes || echo no)"

rc=0
out="$(cd "$ADOPT" && GROUNDHOLD="$OLDPWD/$CLI" bash "$OLDPWD/scripts/adopt-candidate.sh" \
  --discovery discovery.json --resource "$res" \
  --contract orders-db --capability orders-primary \
  --ledger ledger.ndjson --at "$AT" 2>&1)" || rc=$?
report "adopt-candidate runs the published path" 0 "$rc"
case "$out" in
  *"adopted: orders-db/orders-primary -> $res"*)
    report "adopt-candidate reports the binding it made" yes yes ;;
  *) report "adopt-candidate reports the binding it made" yes no ;;
esac

# The generated contract must actually constrain something. An adoption that declares
# nothing confirms nothing, which is the whole point of the D606 guard — asserted here
# on the path that succeeds, not only on the one that refuses.
cons="$(grep -cE '^[[:space:]]*- id:' "$ADOPT/orders-db.contract.yaml" 2>/dev/null || echo 0)"
report "adopt-candidate generates a constrained contract" yes "$([ "$cons" -ge 1 ] && echo yes || echo no)"

# The binding is the claim: the ledger must name the discovered resource.
bound=no
grep -q "$res" "$ADOPT/ledger.ndjson" 2>/dev/null && bound=yes
report "adopt-candidate binds the resource in the ledger" yes "$bound"

echo
if [ "$fail" -gt 0 ]; then
  echo "$pass passed, $fail FAILED — a shipped example does not work"
  exit 1
fi
echo "$pass example checks passed"
