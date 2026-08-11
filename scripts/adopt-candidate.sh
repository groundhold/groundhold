#!/usr/bin/env bash
# adopt-candidate — take a resource from `groundhold discover` output and adopt
# it under a contract in one shot: generate the contract + candidate from
# what groundhold observed, publish, adopt (binds the LEDGER, never the cloud),
# and optionally export into a console seed dir.
#
# This is the command-line counterpart of the console's "how to adopt"
# recipe. The console is read-only by design and cannot run adopt; this can.
# It invents nothing: the candidate is built from the discovery's own
# observations, so adoption confirms every declared attribute against the
# same reality groundhold measured.
set -euo pipefail

GROUNDHOLD="${GROUNDHOLD:-groundhold}"

usage() {
  cat >&2 <<EOF
usage: adopt-candidate.sh --discovery <discover.json> --resource <providerId>
         --contract <name> --capability <cap>
         [--ledger <ledger.ndjson>] [--env <env>] [--owner <id>]
         [--at <RFC3339>] [--seed <dir>]

  --discovery  a \`groundhold discover\` document (its resources[] is the menu)
  --resource   the providerId to adopt (e.g. s3:eu-central-1:my-bucket)
  --contract   the obligation's name — your word for what must be true
  --capability the capability id, used in the contract, candidate, and --map
  --ledger     the append-only ledger file (or set GROUNDHOLD_LEDGER instead)
  --env        environment lane (default: adopted)
  --owner      accountable human (default: \$USER@localhost)
  --at         explicit timestamp (default: now, UTC RFC3339)
  --seed       if set, export + verify are written here (console picks them up)

Env: GROUNDHOLD overrides the groundhold binary (default: groundhold on PATH).
EOF
  exit 2
}

DISCOVERY="" RESOURCE="" CONTRACT="" CAPABILITY="" LEDGER=""
ENVIRONMENT="adopted" OWNER="${USER:-op}@localhost" AT="" SEED=""
while [ $# -gt 0 ]; do
  case "$1" in
    --discovery) DISCOVERY="$2"; shift 2;;
    --resource) RESOURCE="$2"; shift 2;;
    --contract) CONTRACT="$2"; shift 2;;
    --capability) CAPABILITY="$2"; shift 2;;
    --ledger) LEDGER="$2"; shift 2;;
    --env) ENVIRONMENT="$2"; shift 2;;
    --owner) OWNER="$2"; shift 2;;
    --at) AT="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "unknown flag: $1" >&2; usage;;
  esac
done
[ -n "$DISCOVERY$RESOURCE$CONTRACT$CAPABILITY$LEDGER" ] || usage
for req in DISCOVERY RESOURCE CONTRACT CAPABILITY; do
  [ -n "${!req}" ] || { echo "missing --$(echo "$req" | tr A-Z a-z)" >&2; usage; }
done
# the ledger may come from --ledger or GROUNDHOLD_LEDGER (the flag wins)
[ -n "$LEDGER" ] || LEDGER="${GROUNDHOLD_LEDGER:-}"
[ -n "$LEDGER" ] || { echo "need --ledger or GROUNDHOLD_LEDGER in the environment" >&2; usage; }
[ -f "$DISCOVERY" ] || { echo "no such discovery file: $DISCOVERY" >&2; exit 1; }
[ -n "$AT" ] || AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Build contract.yaml + candidate.yaml from the discovery's observations for
# the chosen resource. Python does the JSON->YAML shaping; it declares only
# what groundhold observed, so adoption cannot refuse on an unobservable claim.
CONTRACT="$CONTRACT" CAPABILITY="$CAPABILITY" RESOURCE="$RESOURCE" \
ENVIRONMENT="$ENVIRONMENT" OWNER="$OWNER" WORK="$WORK" \
python3 - "$DISCOVERY" <<'PY'
import json, os, sys
doc = json.load(open(sys.argv[1]))
disc = doc.get("discovery", doc)
provider = disc.get("provider", "")
rid = os.environ["RESOURCE"]
res = next((r for r in disc.get("resources", []) if r.get("providerId") == rid), None)
if res is None:
    sys.exit(f"resource {rid!r} not in the discovery document")

CAP = os.environ["CAPABILITY"]
CON = os.environ["CONTRACT"]
rtype = res.get("resourceType", "")
prefix = rid.split(":", 1)[0]
# driver service names differ from a few providerId prefixes
svc = {"ecredis": "elasticache", "gredis": "redis", "aredis": "rediscache",
       "sbq": "servicebus", "sbt": "servicebus", "flexpg": "flexpostgres"}.get(prefix, prefix)

obs = res.get("observations", [])
# D606: this script's header promises that "adoption confirms every declared attribute
# against the same reality groundhold measured". With an empty observation list it
# generated a contract with ZERO hard constraints, adopted it, and printed `adopted` —
# a confirmation of nothing, in the tool's own confident words. discover appends a
# resource with whatever the driver returned, empty included, so the input is reachable
# by construction rather than hypothetical.
if not obs:
    sys.stderr.write(
        f"adopt-candidate: the discovery document carries NO observed attributes for "
        f"{rid!r}.\n"
        "A contract generated from them would have zero constraints, and adopting it "
        "would confirm nothing while reporting success. Re-run discover for this "
        "resource, or adopt it by hand with the attributes you mean to hold.\n")
    sys.exit(3)
def yval(v):
    if isinstance(v, bool): return "true" if v else "false"
    if isinstance(v, (int, float)): return str(v)
    return str(v)

cons = "\n".join(
    f"""    - id: c-{o['path'].replace('.', '-').lower()}
      subject: {CAP}
      path: {o['path']}
      op: equals
      value: {yval(o['value'])}
      verify: {{ method: static }}""" for o in obs)
attrs = "\n".join(f"      {o['path']}: {yval(o['value'])}" for o in obs)

with open(os.path.join(os.environ["WORK"], "contract.yaml"), "w") as f:
    f.write(f"""apiVersion: contract/v0.1
kind: InfrastructureContract
meta: {{ id: {CON}, owner: {os.environ['OWNER']}, environment: {os.environ['ENVIRONMENT']}, version: 1 }}
capabilities:
  - id: {CAP}
    type: {rtype}
constraints:
  hard:
{cons}
""")
with open(os.path.join(os.environ["WORK"], "candidate.yaml"), "w") as f:
    f.write(f"""apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: {CON}
capabilities:
  {CAP}:
    provider: {provider}
    service: {svc}
    attributes:
{attrs}
""")
print(provider)
PY
PROVIDER="$(RESOURCE="$RESOURCE" python3 -c 'import json,os,sys;d=json.load(open(sys.argv[1]));print((d.get("discovery",d)).get("provider",""))' "$DISCOVERY")"

echo "→ contract + candidate generated for $RESOURCE ($PROVIDER)" >&2
"$GROUNDHOLD" validate "$WORK/contract.yaml" >&2

echo "→ publish" >&2
"$GROUNDHOLD" publish "$WORK/contract.yaml" --ledger "$LEDGER" --actor "$OWNER" --at "$AT" >/dev/null

echo "→ adopt (binds the ledger, never the cloud)" >&2
"$GROUNDHOLD" adopt "$WORK/contract.yaml" "$WORK/candidate.yaml" --ledger "$LEDGER" \
  --map "$CAPABILITY=$RESOURCE" --provider "$PROVIDER" --at "$AT"

if [ -n "$SEED" ]; then
  mkdir -p "$SEED"
  "$GROUNDHOLD" export --ledger "$LEDGER" --format ndjson > "$SEED/export-$CONTRACT.ndjson"
  "$GROUNDHOLD" verify "$WORK/contract.yaml" "$WORK/candidate.yaml" --json > "$SEED/verify-$CONTRACT.json"
  echo "→ exported to $SEED (export-$CONTRACT.ndjson, verify-$CONTRACT.json) — the console will pick it up" >&2
fi
# D671: the two generated documents are the input to the NEXT step the skill
# names ("trim the contract, then re-publish"), and they were written into a
# mktemp directory this script deletes on exit, with the path never printed. Step 4
# asked the operator to edit a file step 3 had removed. They are kept beside the
# ledger, and their paths are said out loud.
KEEP="$(dirname "$LEDGER")"
cp "$WORK/contract.yaml" "$KEEP/$CONTRACT.contract.yaml"
cp "$WORK/candidate.yaml" "$KEEP/$CONTRACT.candidate.yaml"
echo "→ generated documents kept: $KEEP/$CONTRACT.contract.yaml, $KEEP/$CONTRACT.candidate.yaml" >&2
echo "adopted: $CONTRACT/$CAPABILITY -> $RESOURCE" >&2
