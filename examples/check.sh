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

# D1246: the ONBOARDING PROOF, exactly as spec/onboarding.md and the
# onboard-existing skill now describe it. Both used to say a converge straight
# after `adopt` "must report converged without executing anything", and that a
# planned change means the draft is wrong — which sent an operator back to
# redraft over a CLAIM no redraft can remove. Takeover is two acts; this pins
# both, and pins that the middle step is a refusal rather than a green.
ONB="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$ONB"' EXIT
"$CLI" discover --provider fake --at "$AT" --json > "$ONB/d.json" 2>/dev/null || true
rc=0
GROUNDHOLD="$CLI" scripts/adopt-candidate.sh --discovery "$ONB/d.json"   --resource fake:existing-db --contract legacy --capability db   --ledger "$ONB/l.ndjson" --at "$AT" >/dev/null 2>&1 || rc=$?
report "onboarding: adopt-candidate.sh adopts a discovered resource" 0 "$rc"
rc=0
out="$("$CLI" converge "$ONB/legacy.contract.yaml" "$ONB/legacy.candidate.yaml" \
  --ledger "$ONB/l.ndjson" --provider fake --at "$AT" 2>&1)" || rc=$?
report "onboarding: converge after adopt plans a claim (not converged)" 2 "$rc"
case "$out" in
  *"claim a-claim-db"*) report "onboarding: the planned action IS the claim" yes yes ;;
  *)                    report "onboarding: the planned action IS the claim" yes no ;;
esac
rc=0
"$CLI" converge "$ONB/legacy.contract.yaml" "$ONB/legacy.candidate.yaml" \
  --ledger "$ONB/l.ndjson" --provider fake --at "$AT" --yes >/dev/null 2>&1 || rc=$?
report "onboarding: converge --yes executes the claim" 0 "$rc"
rc=0
out="$("$CLI" converge "$ONB/legacy.contract.yaml" "$ONB/legacy.candidate.yaml" \
  --ledger "$ONB/l.ndjson" --provider fake --at "$AT" 2>&1)" || rc=$?
report "onboarding: the no-op proof passes only AFTER the claim" 0 "$rc"
case "$out" in
  *"already matches the candidate"*) report "onboarding: proof is a true no-op" yes yes ;;
  *)                                 report "onboarding: proof is a true no-op" yes no ;;
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

# The README's agent-facing section makes a promise about refusals. It is the promise
# an agent is written against, so it is worth measuring rather than believing: take a
# GENUINE refusal (a well-formed request the tool declines, exit 2) and read what it
# actually carries.
REF="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$NEW" "$ADOPT" "$REF"' EXIT
rc=0
"$CLI" verify examples/lifecycle/2-refused.contract.yaml \
               examples/lifecycle/2-refused.candidate.yaml --json > "$REF/refusal.json" 2>/dev/null || rc=$?
report "a violating pair is refused" 2 "$rc"

has_code=no; grep -q '"code"' "$REF/refusal.json" && has_code=yes
report "the refusal carries a machine code" yes "$has_code"

# And the half the README used to overpromise. `next` is deliberately OMITTED where no
# honest invocation-specific step exists, so its absence is not a defect — claiming it
# unconditionally is. The check is conditional on the measurement: only when a refusal
# carries no `next` must the README stop promising one on every refusal.
has_next=no; grep -q '"next"' "$REF/refusal.json" && has_next=yes
if [ "$has_next" = no ]; then
  # Prose wraps. A line-oriented grep for a sentence fragment can never match one that
  # spans two lines, so it would pass over the very claim it exists to catch — the whole
  # text is folded to one line first.
  overclaim=no
  tr '\n' ' ' < README.md | tr -s ' ' \
    | grep -q 'carries a machine code and a `next` step' && overclaim=yes
  report "README does not promise a next it never emits" no "$overclaim"
fi

# `--explain` is documented in the CLI's own machine contract as attaching remediation
# to JSON refusals. It used to change nothing on four of the verbs most likely to refuse,
# because each marshalled its own JSON and never reached the emitter that does the
# attaching. A flag that silently ignores you is worse than one that does not exist, so
# the promise is measured per verb: same invocation, with and without the flag, and the
# output must differ.
EX="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$NEW" "$ADOPT" "$REF" "$EX"' EXIT
explains() {
  name="$1"; shift
  "$CLI" "$@" --ledger "$EX/$name-a.jsonl" --json          > "$EX/$name.plain" 2>/dev/null || true
  "$CLI" "$@" --ledger "$EX/$name-b.jsonl" --json --explain > "$EX/$name.expl"  2>/dev/null || true
  # The refusal must be real, else this measures nothing.
  if ! grep -q '"code"' "$EX/$name.plain"; then
    report "$name refuses with a code (precondition)" yes no
    return
  fi
  if cmp -s "$EX/$name.plain" "$EX/$name.expl"; then
    report "--explain changes $name's refusal" yes no
  else
    report "--explain changes $name's refusal" yes yes
  fi
}
explains verify   verify   examples/lifecycle/2-refused.contract.yaml examples/lifecycle/2-refused.candidate.yaml
explains audit    audit    examples/lifecycle/1-create.contract.yaml --at "$AT"
explains converge converge examples/lifecycle/2-refused.contract.yaml examples/lifecycle/2-refused.candidate.yaml --provider fake --at "$AT" --yes

# plan takes no --ledger, so it is measured on its own.
"$CLI" plan spec/examples/orders-production.contract.yaml \
       spec/examples/candidates/gcp-cloudsql.candidate.yaml --vocab spec/vocab \
       --at "$AT" --json > "$EX/plan.plain" 2>/dev/null || true
"$CLI" plan spec/examples/orders-production.contract.yaml \
       spec/examples/candidates/gcp-cloudsql.candidate.yaml --vocab spec/vocab \
       --at "$AT" --json --explain > "$EX/plan.expl" 2>/dev/null || true
if grep -q '"code"' "$EX/plan.plain" && ! cmp -s "$EX/plan.plain" "$EX/plan.expl"; then
  report "--explain changes plan's refusal" yes yes
else
  report "--explain changes plan's refusal" yes no
fi

# The published CI workflow (examples/ci/github-actions.yml) is a file a reader COPIES
# into their own repository. Its centre is not a command but a decision: `plan` exits 2
# for a family of reasons, and the step must route on the `code` field — treat
# nothing-to-change as converged, re-raise everything else. Two design entries were
# spent on that block (a pipeline whose status came from `tee` so the gate could not
# fail, and an exit-2 family read as a single verdict so a violated hard constraint
# merged green). Nothing has ever executed it.
#
# So execute it. The block is EXTRACTED from the published YAML rather than copied
# here — a copy would drift, and then this would be testing a snapshot of advice
# nobody follows. Only the three paths are substituted, because the reader's repository
# is where the originals live.
CI="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$NEW" "$ADOPT" "$REF" "$EX" "$CI"' EXIT

python3 - "$CI/routing.sh" <<'PYEOF' || true
import re, sys
y = open('examples/ci/github-actions.yml', encoding='utf-8').read()
m = re.search(r'name: forecast the sealed plan \(advisory\).*?run: \|\n(.*?)(?=\n      - |\n\n  [a-z]|\Z)',
              y, re.S)
if not m:
    sys.exit("could not find the routing step in the published workflow")
body = "\n".join(l[10:] if l.startswith(' ' * 10) else l for l in m.group(1).split("\n"))
open(sys.argv[1], "w", encoding="utf-8").write(body)
PYEOF

if [ ! -s "$CI/routing.sh" ]; then
  report "the published CI workflow still has its exit-2 routing step" yes no
else
  report "the published CI workflow still has its exit-2 routing step" yes yes

  # The reader's paths, replaced by ours per invocation. Everything else — the grep,
  # the exit codes, the re-raise — is the published text.
  # Absolute paths: the block is executed from a scratch directory, exactly as a
  # reader's checkout would be a different directory from ours.
  run_routing() {  # <contract> <candidate> <ledger>
    cp "$CI/routing.sh" "$CI/r.sh"
    sed -i "s|contracts/prod.contract.yaml|$PWD/$1|g; s|candidates/prod.candidate.yaml|$PWD/$2|g; \
            s|state/prod.jsonl|$3|g; s|bin/groundhold-go|$PWD/$CLI|g" "$CI/r.sh"
    ( cd "$CI" && bash ./r.sh >/dev/null 2>&1 )
  }

  # A converged pair: plan exits 2 with nothing-to-change, and the step must call that
  # success. This is the half that must not become a false alarm.
  # The extracted block computes its own `AT` — that is the point of it, a CI job reads
  # the world at one instant. So the state it reads must be built on the same clock:
  # converging at the harness's fixed stamp leaves observations the block then calls
  # stale, and the answer becomes observation-required rather than nothing-to-change.
  NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "$CLI" converge examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
    --ledger "$CI/converged.jsonl" --provider fake --at "$NOW" --yes >/dev/null 2>&1 || true
  rc=0
  run_routing examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
              "$CI/converged.jsonl" || rc=$?
  report "CI routing calls nothing-to-change converged" 0 "$rc"

  # A violating pair: plan exits 2 with not-executable, and the step must RE-RAISE.
  # This is the one that merged a broken pull request green.
  rc=0
  run_routing examples/lifecycle/2-refused.contract.yaml examples/lifecycle/2-refused.candidate.yaml \
              "$CI/violating.jsonl" || rc=$?
  report "CI routing re-raises a violated hard constraint" 2 "$rc"
fi

# spec/errors.md makes a promise an agent is written against: "`plan` on exit 2
# additionally prints exactly ONE refusal object (`{status, code?, reasons}`) to
# stdout ... and the success document stays self-discriminating via its top-level
# `plan` key". It is true. Nothing kept it true — exit 2 is a FAMILY, reached from
# several places in the compiler, and any one of them returning before it emits leaves
# an agent routing on stdout with nothing to route on.
PL="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$NEW" "$ADOPT" "$REF" "$EX" "$CI" "$PL"' EXIT

# Count top-level JSON documents on stdout: 0 means the promise is broken by silence,
# 2+ by chatter, -1 by malformed output.
count_json() {
  python3 -c '
import sys, json
s = sys.stdin.read().strip()
if not s:
    print(0); raise SystemExit
d = json.JSONDecoder(); i = 0; n = 0
while i < len(s):
    while i < len(s) and s[i].isspace(): i += 1
    if i >= len(s): break
    try: _, i = d.raw_decode(s, i)
    except Exception: print(-1); raise SystemExit
    n += 1
print(n)'
}
plan_code() { python3 -c 'import sys,json; print(json.load(sys.stdin).get("code","-"))' 2>/dev/null || echo "-"; }

# Four genuinely different roads to exit 2. The clock matters: a converged fixture must
# be built on the stamp the plan will read, or the answer becomes observation-required
# (which is itself one of the four, built deliberately below).
PNOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
"$CLI" converge examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger "$PL/fresh.jsonl" --provider fake --at "$PNOW" --yes >/dev/null 2>&1 || true
"$CLI" converge examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger "$PL/stale.jsonl" --provider fake --at "$AT" --yes >/dev/null 2>&1 || true

codes=""
check_one_object() {  # <label> <outfile> <args...>
  label="$1"; outf="$2"; shift 2
  rc=0
  "$CLI" plan "$@" > "$outf" 2>/dev/null || rc=$?
  report "plan refuses ($label)" 2 "$rc"
  report "plan prints exactly one object ($label)" 1 "$(count_json < "$outf")"
  codes="$codes $(plan_code < "$outf")"
}

check_one_object "violated"  "$PL/a.json" examples/lifecycle/2-refused.contract.yaml \
  examples/lifecycle/2-refused.candidate.yaml --at "$PNOW"
check_one_object "converged" "$PL/b.json" examples/laptop/laptop.contract.yaml \
  examples/laptop/laptop.candidate.yaml --ledger "$PL/fresh.jsonl" --at "$PNOW"
check_one_object "unproven"  "$PL/c.json" spec/examples/orders-production.contract.yaml \
  spec/examples/candidates/gcp-cloudsql.candidate.yaml --vocab spec/vocab --at "$PNOW"
check_one_object "stale"     "$PL/d.json" examples/laptop/laptop.contract.yaml \
  examples/laptop/laptop.candidate.yaml --ledger "$PL/stale.jsonl" --at "$PNOW"

# Vacuity: name the codes rather than count them. Four roads produce THREE codes — a
# violated hard constraint and an unproven one are both `not-executable`, which is
# correct and is the kind of thing a bare count hides. If this collapses to one code the
# check tested a single path four times and would keep passing while the others broke;
# if a code changes, the sentence in spec/errors.md that lists the exit-2 family needs
# rereading before this line is edited.
distinct="$(printf '%s\n' $codes | sort -u | tr '\n' ' ' | sed 's/ *$//')"
report "the refusals span the documented exit-2 family" \
  "not-executable nothing-to-change observation-required" "$distinct"

# The other half of the same sentence: success is self-discriminating, so a consumer
# can tell a plan from a refusal without reading the exit code.
rc=0
"$CLI" plan examples/lifecycle/1-create.contract.yaml examples/lifecycle/1-create.candidate.yaml \
  --at "$PNOW" > "$PL/ok.json" 2>/dev/null || rc=$?
report "plan succeeds on an executable pair" 0 "$rc"
has_plan=no
python3 -c 'import sys,json; sys.exit(0 if "plan" in json.load(open(sys.argv[1])) else 1)' \
  "$PL/ok.json" 2>/dev/null && has_plan=yes
report "the success document carries a top-level plan key" yes "$has_plan"

# The other half of the same spec section: the verbs listed as SILENT must print no
# green word at all. "Success silence beats generic reassurance" — a green word after
# `observe` or `probe` would claim the world is healthy when the verb only claims a
# measurement was recorded. Silence is not implemented by the word table; it is each
# verb declining to banner, which is exactly the kind of per-site decision that drifts.
SIL="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$NEW" "$ADOPT" "$REF" "$EX" "$CI" "$PL" "$SIL"' EXIT
"$CLI" converge examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger "$SIL/l.jsonl" --provider fake --at "$AT" --yes >/dev/null 2>&1 || true

silent_verb() {  # <label> <args...>
  label="$1"; shift
  banner="$("$@" 2>&1 >/dev/null | grep -oE '\b(PROVEN|CONVERGED|APPLIED|SEALED|OK)\b' | tail -1 || true)"
  report "$label banners nothing on success" "" "$banner"
}
silent_verb validate "$CLI" validate examples/laptop/laptop.contract.yaml
silent_verb hash     "$CLI" hash examples/laptop/laptop.contract.yaml
silent_verb explain  "$CLI" explain not-executable
silent_verb export   "$CLI" export --ledger "$SIL/l.jsonl"
silent_verb deposed  "$CLI" deposed --ledger "$SIL/l.jsonl"

# And the paired positive, so the check cannot pass by the banners having vanished
# everywhere: verify still says PROVEN.
proven="$("$CLI" verify examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --json 2>&1 >/dev/null | grep -oE '\bPROVEN\b' | tail -1 || true)"
report "verify still banners PROVEN" PROVEN "$proven"

# spec/capsule.md publishes a numbered sequence of six verification checks and one
# sentence that binds them: "Any refusal is corruption-class evidence: exit 5." A capsule
# is evidence that TRAVELS — verified with "no ledger, no groundhold deployment, no
# filesystem trust" — so the receiver has nothing but the exit code to route on. A check
# that refused with 1 or 2 instead would read as a bad invocation rather than a tampered
# proof, and a receiver could reasonably retry it.
CAP="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$NEW" "$ADOPT" "$REF" "$EX" "$CI" "$PL" "$SIL" "$CAP"' EXIT
CNOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
"$CLI" converge examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger "$CAP/l.jsonl" --provider fake --at "$CNOW" --yes >/dev/null 2>&1 || true
"$CLI" capsule db --ledger "$CAP/l.jsonl" > "$CAP/clean.json" 2>/dev/null || true
"$CLI" anchor --ledger "$CAP/l.jsonl" > "$CAP/anchor.json" 2>/dev/null || true

# The positive control comes first: without it every assertion below could be satisfied
# by a capsule that never verified at all.
rc=0; "$CLI" capsule --verify "$CAP/clean.json" >/dev/null 2>&1 || rc=$?
report "a clean capsule verifies" 0 "$rc"
rc=0; "$CLI" capsule --verify "$CAP/clean.json" --check "$CAP/anchor.json" >/dev/null 2>&1 || rc=$?
report "a capsule verifies against its own anchor" 0 "$rc"

python3 - "$CAP" <<'PYEOF' || true
import json, sys, copy
d = sys.argv[1]
b = json.load(open(f"{d}/clean.json"))
def w(n, o): json.dump(o, open(f"{d}/{n}.json", "w"))
c = copy.deepcopy(b); c["eventHashAlg"] = "sha3-256"; w("alg", c)          # check 1
c = copy.deepcopy(b); c["events"][3]["event"]["capabilities"] = ["other"]; w("cap", c)  # check 2
c = copy.deepcopy(b)                                                       # check 3
ev = c["events"][2]["event"]
if isinstance(ev.get("prev"), dict) and ev["prev"]:
    ev["prev"][list(ev["prev"])[0]] = "sha256:" + "0" * 40
w("link", c)
c = copy.deepcopy(b); c["head"] = "sha256:" + "1" * 40; w("head", c)       # check 4
c = copy.deepcopy(b); c["asOf"] = "2020-01-01T00:00:00Z"; w("asof", c)     # check 4, other half
a = json.load(open(f"{d}/anchor.json"))                                    # check 6
def bump(o):
    if isinstance(o, dict):
        return {k: ("sha256:" + "3" * 40) if k == "db" and isinstance(v, str) else bump(v)
                for k, v in o.items()}
    return o
w("badanchor", bump(copy.deepcopy(a)))
PYEOF

# Each of the six, by the number the spec gives it. Asserting FIVE, not merely non-zero:
# the exit code IS the claim.
corrupt() {  # <label> <file> [extra args...]
  label="$1"; file="$2"; shift 2
  rc=0
  "$CLI" capsule --verify "$file" "$@" >/dev/null 2>&1 || rc=$?
  report "$label refuses corruption-class (exit 5)" 5 "$rc"
}
corrupt "1 unknown hash algebra"      "$CAP/alg.json"
# NOT labelled "check 2". Editing an event so it stops listing the capability changes
# its canonical hash, so the recomputed tip stops matching `head` and check 4 fires
# first — verified by disabling check 2 alone, which changed nothing. That is defence in
# depth rather than a redundant check, and the honest label is what the input proves: a
# foreign event does not travel in this capsule.
corrupt "a foreign event"             "$CAP/cap.json"
corrupt "3 broken linkage"            "$CAP/link.json"
corrupt "4 head not the recomputed tip" "$CAP/head.json"
corrupt "4 asOf not the tip's time"   "$CAP/asof.json"
corrupt "5 --trust by a foreign key"  "$CAP/clean.json" --trust 0000000000000000000000000000000000000000000000000000000000000000
corrupt "6 anchor pinning another head" "$CAP/clean.json" --check "$CAP/badanchor.json"

# spec/outputs.schema.json is the contract a machine consumer validates against, and
# versioning.md promises the shapes are stable — "outputs may GROW fields (consumers
# must tolerate unknown fields)". Growing is safe; a required field LEAVING is not, and
# nothing compared the schema to what the verbs actually print.
#
# D1156: this used to check ONE thing — that every property the schema marks `required`
# was present. Types, enums, `const`, `$ref` and open-map values went unread, and five
# of the twenty-one published shapes were the only ones a real output ever reached. So a
# verb could emit a status outside its own published enum and this printed PASS. It did:
# `repair` gained a `version-ahead` status and finding-kind in D1154, both outside the
# enums here, and a consumer validating against the schema would have rejected output
# the runtime was right to produce.
#
# Extra properties are still NOT flagged — the promise above allows growth, and the
# schema declares `additionalProperties: false` nowhere, so the two agree. Where
# `additionalProperties` IS a schema (the open maps: bindings, heads, outcomes) its
# values are now validated, which is the same rule read properly rather than skipped.
SCH="$(mktemp -d)"
trap 'rm -rf "$LEDGER" "$LIFE" "$NEW" "$ADOPT" "$REF" "$EX" "$CI" "$PL" "$SIL" "$CAP" "$SCH"' EXIT
SNOW="$(date -u +%FT%TZ)"

"$CLI" verify examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --json > "$SCH/verifyReport.json" 2>/dev/null || true
"$CLI" converge examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger "$SCH/l.jsonl" --provider fake --at "$SNOW" --yes --json \
  > "$SCH/convergeResult.json" 2>/dev/null || true
"$CLI" audit examples/laptop/laptop.contract.yaml --ledger "$SCH/l.jsonl" --at "$SNOW" \
  --json > "$SCH/auditResult.json" 2>/dev/null || true
"$CLI" plan examples/lifecycle/2-refused.contract.yaml examples/lifecycle/2-refused.candidate.yaml \
  --at "$SNOW" --json > "$SCH/planRefusal.json" 2>/dev/null || true
"$CLI" discover --provider fake --at "$SNOW" > "$SCH/discoverResult.json" 2>/dev/null || true
"$CLI" publish examples/laptop/laptop.contract.yaml --ledger "$SCH/p.jsonl" --at "$SNOW" \
  --actor harness > "$SCH/publishResult.json" 2>/dev/null || true
# D1156: eleven more shapes, because a schema entry no real output ever reaches is a
# description of the runtime rather than a check on it.
"$CLI" observe examples/laptop/laptop.contract.yaml --ledger "$SCH/l.jsonl" \
  --provider fake --at "$SNOW" --json > "$SCH/observeResult.json" 2>/dev/null || true
"$CLI" probe examples/laptop/laptop.contract.yaml --ledger "$SCH/l.jsonl" \
  --provider fake --at "$SNOW" --json > "$SCH/probeResult.json" 2>/dev/null || true
"$CLI" horizon --ledger "$SCH/l.jsonl" --at "$SNOW" \
  --contract examples/laptop/laptop.contract.yaml --within 86400 --json \
  > "$SCH/horizonResult.json" 2>/dev/null || true
"$CLI" deposed --ledger "$SCH/l.jsonl" --json > "$SCH/deposedResult.json" 2>/dev/null || true
"$CLI" explain not-executable --json > "$SCH/explain.json" 2>/dev/null || true
"$CLI" anchor --ledger "$SCH/l.jsonl" > "$SCH/anchorDocument.json" 2>/dev/null || true
"$CLI" anchor --ledger "$SCH/l.jsonl" --check "$SCH/anchorDocument.json" \
  > "$SCH/anchorCheck.json" 2>/dev/null || true
"$CLI" export --ledger "$SCH/l.jsonl" 2>/dev/null | head -1 > "$SCH/exportRecord.json" || true
# repair's two shapes need a ledger it refuses. An event type from a future build is the
# one that exercises the version-ahead branch D1154 added — the branch whose statuses
# were outside this schema until D1156.
python3 - "$SCH" <<'MKEOF' 2>/dev/null || true
import json, sys, hashlib, os
d = sys.argv[1]
src = os.path.join(d, "l.jsonl")
if os.path.exists(src):
    lines = [l for l in open(src).read().split("\n") if l.strip()]
    if lines:
        doc = json.loads(lines[0])
        doc["event"]["type"] = "observation.telepathic"
        doc["type"] = "observation.telepathic"
        open(os.path.join(d, "ahead.jsonl"), "w").write(json.dumps(doc) + "\n")
MKEOF
if [ -f "$SCH/ahead.jsonl" ]; then
  "$CLI" repair --ledger "$SCH/ahead.jsonl" > "$SCH/repairDiagnosis.json" 2>/dev/null || true
  fp="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("fingerprint",""))' "$SCH/repairDiagnosis.json" 2>/dev/null || true)"
  if [ -n "$fp" ]; then
    "$CLI" repair --ledger "$SCH/ahead.jsonl" --quarantine --fingerprint "$fp" \
      > "$SCH/repairResult.json" 2>/dev/null || true
  fi
fi

missing="$(python3 - "$SCH" <<'PYEOF' || true
import json, os, sys

sys.path.insert(0, "examples")
from schemacheck import errors, selftest          # noqa: E402

d = sys.argv[1]
root = json.load(open("spec/outputs.schema.json"))
defs = root["$defs"]

bad = []
checked = 0
for name in sorted(defs):
    path = os.path.join(d, name + ".json")
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        continue                       # only the shapes this harness can produce
    try:
        doc = json.load(open(path))
    except Exception as e:
        bad.append("%s: output is not JSON (%s)" % (name, e))
        continue
    checked += 1
    for p, msg in errors(doc, defs[name], defs):
        bad.append("%s: %s: %s" % (name, p or "(root)", msg))

if checked < 12:
    bad.append("only %d of %d published shapes were produced — the harness stopped "
               "exercising the verbs and this check would pass over almost nothing"
               % (checked, len(defs)))
bad += selftest()
print("; ".join(bad))
PYEOF
)"
report "real output validates against the published schema" "" "$missing"

# D1157: the same question on the INPUT side. `spec/contract.schema.json` and
# `spec/candidate.schema.json` are what a stranger validates a document against before
# it ever reaches this runtime, and nothing had run a real one through either. One
# shipped example failed: the voice track's drafted contract held two assumptions with a
# `source` citing where they came from and no `statement` of what was assumed — which
# the schema publishes as required, which every other assumption in the tree carries,
# and which neither implementation read. `validate` called that document OK.
#
# Discovery is the same `find` the checks above use, so a document that ships is a
# document that is checked; a hand-typed list is how D692 missed the first contract.
mapfile -t SCHEMA_DOCS < <(find examples spec/examples \
  \( -name '*.contract.yaml' -o -name '*.candidate.yaml' \) | sort)
missing="$(python3 - "${SCHEMA_DOCS[@]}" <<'PYEOF' || true
import json, re, sys, yaml

# The SAME checker as the output block above — one copy in examples/schemacheck.py,
# imported by both. Two copies would be free to agree with each other by luck and
# diverge on the case that matters, which is the shape half this record is about.
sys.path.insert(0, "examples")
from schemacheck import errors, selftest              # noqa: E402

schemas = {"contract": json.load(open("spec/contract.schema.json")),
           "candidate": json.load(open("spec/candidate.schema.json"))}
bad = []
counts = {"contract": 0, "candidate": 0}
for path in sys.argv[1:]:
    kind = "contract" if path.endswith(".contract.yaml") else "candidate"
    try:
        doc = yaml.safe_load(open(path))
    except Exception as e:
        bad.append("%s: does not parse as YAML (%s)" % (path, e))
        continue
    counts[kind] += 1
    schema = schemas[kind]
    for p, msg in errors(doc, schema, schema.get("$defs", {})):
        bad.append("%s: %s: %s" % (path, p or "(root)", msg))
bad += selftest()
for kind, n in sorted(counts.items()):
    if n < 4:
        bad.append("only %d %s documents were found — the discovery broke and this "
                   "check would pass over almost nothing" % (n, kind))
print("; ".join(bad))
PYEOF
)"
report "every shipped document validates against its published schema" "" "$missing"

# D1158: and the third published schema, against the artefact it exists for. The ledger
# the run above produced is validated event by event — the one document type
# `spec/state.schema.json` describes, which until now it did not describe at all: its
# root carried no `type`, no `$ref` and no `properties`, so every document was a valid
# State Model v0, the number 42 included. Nothing caught that because nothing had ever
# handed it a ledger.
missing="$(python3 - "$SCH/l.jsonl" <<'PYEOF' || true
import json, os, sys

sys.path.insert(0, "examples")
from schemacheck import errors, selftest                # noqa: E402

path = sys.argv[1]
schema = json.load(open("spec/state.schema.json"))
defs = schema.get("$defs", {})
bad = []
seen = set()
n = 0
if not os.path.exists(path):
    bad.append("the converge above produced no ledger, so the state schema met nothing")
else:
    for i, line in enumerate(open(path), 1):
        line = line.strip()
        if not line:
            continue
        n += 1
        try:
            doc = json.loads(line)
        except Exception as e:
            bad.append("ledger line %d: not JSON (%s)" % (i, e))
            continue
        seen.add((doc.get("event") or {}).get("type"))
        for p, msg in errors(doc, schema, defs):
            bad.append("ledger line %d: %s: %s" % (i, p or "(root)", msg))
# A floor on BOTH counts: a truncated ledger, or one carrying a single kind of event,
# validates almost nothing while reading exactly like a clean run.
if n < 8 or len(seen) < 5:
    bad.append("only %d events of %d distinct types reached the state schema — the run "
               "stopped producing a real ledger and this check would pass over nothing"
               % (n, len(seen)))
# The schema must also REFUSE. It accepted every document ever handed to it until
# D1158, and a validator that cannot say no is not one.
for name, doc in (("the number 42", 42), ("a bare object", {}),
                  ("an export record", {"index": 0, "type": "x", "event": {}})):
    if not errors(doc, schema, defs):
        bad.append("the state schema ACCEPTED %s as a valid ledger event — its root "
                   "constrains nothing again" % name)
bad += selftest()
print("; ".join(bad))
PYEOF
)"
report "a real ledger validates against the published state schema" "" "$missing"

echo
if [ "$fail" -gt 0 ]; then
  echo "$pass passed, $fail FAILED — a shipped example does not work"
  exit 1
fi
echo "$pass example checks passed"
