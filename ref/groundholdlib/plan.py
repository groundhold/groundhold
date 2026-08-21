"""Sealed Plan IR v0 — loading + structural validation
(spec/sealed-plan.md, D36). Fail-closed (D19): unknown operations,
dangling or cyclic dependencies, unpinned writes and missing
report-executable preconditions are refused at load.
"""
from __future__ import annotations
import re
from typing import Any


from .yamlcompat import safe_load as _core12_load

from .contract import ContractError, read_document

# D1171: `claim` was missing here while the Go runtime has emitted and executed it
# since D52 — a takeover stamps authorship on an adopted resource, and without it
# adopt → retire produces a plan that cannot apply. So this implementation REFUSED a
# plan our own compiler produces, and `spec/sealed-plan.md` published the six-member
# list beside it. Three copies, two answers, and no case exercised the difference.
OPERATIONS = {"create", "update", "replace", "delete", "adopt", "noop", "claim"}
PRECONDITION_TYPES = {"report-executable", "no-assumed-basis", "within-autonomy",
                      "no-assumed-hard-basis"}  # D195: hard-only, assumed-only gate
RISK_LEVELS = {"none", "possible", "certain"}
REVERSIBILITY = {"R0", "R1", "R2", "R3", "R4"}
# The key sets this document admits, mirroring go/internal/plan/plan.go. D1171: nine
# conformance cases pinned the plan and every one was about a VALUE or a RELATION;
# none about a KEY. `dependsOn` is read optionally, so `dependson:` reads as "no
# dependencies" and apply trusts the graph verbatim for ordering AND fail-isolation.
# The sets are what the COMPILER emits, not what this loader reads.
PLAN_DOC_KEYS = {"apiVersion", "kind", "plan"}
PLAN_BODY_KEYS = {"contract", "environment", "reads", "writes", "actions",
                  "witnessed", "blocked", "unverified", "noop", "preconditions",
                  "advisories"}
PLAN_READS_KEYS = {"contractHash", "candidateHash", "heads", "vocabularies",
                   "toolchain", "provider"}
PLAN_PROVIDER_KEYS = {"name", "project"}
PLAN_ACTION_KEYS = {"id", "capability", "operation", "target", "idempotencyKey",
                    "dependsOn", "changes", "targetProviderId", "targetGeneration",
                    "replaces", "deposed", "fieldReclaim", "emissionAdopt",
                    "requiredPermissions", "references", "folds", "risk"}
PLAN_RISK_KEYS = {"reversibility", "dataLoss", "downtime", "securityExposure",
                  "costDelta", "identityReplacement"}
PLAN_CHANGE_KEYS = {"path", "from", "to", "caveat"}
PLAN_WITNESS_KEYS = {"capability", "provider", "service", "reason"}
PLAN_PRECONDITION_KEYS = {"type"}

_WHY_EXECUTED = ("a plan is executed, and a block the executor does not read "
                 "decides nothing while looking like it does")

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _check_plan_keys(doc: dict, known: set, where: str, why: str) -> None:
    """Refuse a mapping carrying a key nothing reads (D673, D1170, D1171)."""
    unknown = sorted(k for k in doc
                     if k not in known and not str(k).startswith("x-"))
    if unknown:
        raise ContractError(
            f"{where} declares unknown key(s) {', '.join(unknown)} — {why}. "
            "Rename it, or prefix it with `x-` if it is deliberately not "
            "runtime data")


def _require_hash(v: Any, what: str) -> None:
    if not isinstance(v, str) or not _HASH_RE.match(v):
        raise ContractError(f"{what} must be a sha256:<hex> hash")


def _check_risk(aid: str, risk: Any) -> None:
    if not isinstance(risk, dict):
        raise ContractError(f"action {aid}: risk vector is required (D33)")
    _check_plan_keys(risk, PLAN_RISK_KEYS, f"action {aid}: risk",
                     "the risk vector is what the autonomy gate reads (D33); a "
                     "dimension nothing reads is a dimension nothing gates on")
    if risk.get("reversibility") not in REVERSIBILITY:
        raise ContractError(f"action {aid}: invalid reversibility")
    for dim in ("dataLoss", "downtime", "securityExposure"):
        if risk.get(dim) not in RISK_LEVELS:
            raise ContractError(f"action {aid}: invalid risk dimension {dim}")
    if not isinstance(risk.get("identityReplacement"), bool):
        raise ContractError(f"action {aid}: identityReplacement must be a bool")
    cd = risk.get("costDelta")
    if not isinstance(cd, dict) or isinstance(cd.get("amount"), bool) \
            or not isinstance(cd.get("amount"), (int, float)) \
            or not cd.get("currency"):
        raise ContractError(
            f"action {aid}: costDelta must be {{amount, currency}}")


def load_plan(path: str) -> dict[str, Any]:
    doc = _core12_load(read_document(path))
    if not isinstance(doc, dict):
        raise ContractError("plan document is empty or not a mapping")
    if doc.get("kind") != "SealedPlan":
        raise ContractError("kind must be SealedPlan")
    if doc.get("apiVersion") != "plan/v0":
        raise ContractError("apiVersion must be plan/v0")
    _check_plan_keys(doc, PLAN_DOC_KEYS, "sealed plan", _WHY_EXECUTED)
    p = doc.get("plan")
    if not isinstance(p, dict):
        raise ContractError("plan block is required")
    _check_plan_keys(p, PLAN_BODY_KEYS, "plan", _WHY_EXECUTED)
    if not p.get("contract"):
        raise ContractError("plan.contract is required")

    reads = p.get("reads")
    if not isinstance(reads, dict):
        raise ContractError("plan.reads is required (D28: pin the read-set)")
    _check_plan_keys(reads, PLAN_READS_KEYS, "plan.reads",
                     "the read-set is what D28 pins; an entry nothing reads "
                     "pins nothing")
    if isinstance(reads.get("provider"), dict):
        _check_plan_keys(reads["provider"], PLAN_PROVIDER_KEYS,
                         "plan.reads.provider",
                         "this block is the PINNED provider identity (D28); a key "
                         "nothing reads tells a reader something is pinned when "
                         "it is not")
    _require_hash(reads.get("contractHash"), "reads.contractHash")
    _require_hash(reads.get("candidateHash"), "reads.candidateHash")
    heads = reads.get("heads")
    if not isinstance(heads, dict) or not heads:
        raise ContractError("reads.heads must pin a head per capability")
    for cap, h in heads.items():
        if h != "genesis":
            _require_hash(h, f"reads.heads[{cap}]")
    tc = reads.get("toolchain")
    if not isinstance(tc, dict) or not tc.get("compiler") or not tc.get("spec"):
        raise ContractError("reads.toolchain must carry compiler and spec")

    writes = p.get("writes")
    if not isinstance(writes, list) or not writes \
            or not all(isinstance(w, str) for w in writes):
        raise ContractError("plan.writes must be a non-empty list of ids")
    for w in writes:
        if w not in heads:
            raise ContractError(
                f"write {w!r} has no pinned head — you cannot write "
                "what you did not read (D28)")

    actions = p.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ContractError("plan.actions must be a non-empty list")
    ids: set[str] = set()
    deps: dict[str, list[str]] = {}
    for a in actions:
        if not isinstance(a, dict) or not a.get("id"):
            raise ContractError("action missing id")
        aid = a["id"]
        if aid in ids:
            raise ContractError(f"duplicate action id: {aid}")
        ids.add(aid)
        _check_plan_keys(a, PLAN_ACTION_KEYS, f"action {aid}",
                         "`dependsOn` is read OPTIONALLY, so a misspelling is not "
                         "an error — it reads as `no dependencies`, and apply "
                         "trusts the graph verbatim for both ordering and "
                         "fail-isolation")
        if a.get("capability") not in writes:
            raise ContractError(
                f"action {aid}: capability outside plan.writes")
        if a.get("operation") not in OPERATIONS:
            raise ContractError(
                f"action {aid}: unknown operation {a.get('operation')!r}")
        if not a.get("idempotencyKey"):
            raise ContractError(f"action {aid}: idempotencyKey is required (D29)")
        _check_risk(aid, a.get("risk"))
        if a.get("operation") == "delete":
            # D47: a delete pins the exact identity it destroys — a rebind
            # between seal and apply must not redirect it
            if not a.get("targetProviderId"):
                raise ContractError(
                    f"action {aid}: delete requires targetProviderId")
            gen = a.get("targetGeneration")
            if isinstance(gen, bool) or not isinstance(gen, int) or gen < 1:
                raise ContractError(
                    f"action {aid}: delete requires targetGeneration >= 1")
        if a.get("operation") == "update":
            # D46: an update is a reviewed change-set, never an implicit diff
            changes = a.get("changes")
            if not isinstance(changes, list) or not changes:
                raise ContractError(
                    f"action {aid}: update requires a non-empty changes list")
            for ch in changes:
                if isinstance(ch, dict):
                    _check_plan_keys(ch, PLAN_CHANGE_KEYS,
                                     f"action {aid}: change",
                                     "an update is a REVIEWED change-set (D46), "
                                     "and a field nothing reads was never reviewed")
                if not isinstance(ch, dict) or not ch.get("path") \
                        or "to" not in ch:
                    raise ContractError(
                        f"action {aid}: each change needs path and to")
        deps[aid] = list(a.get("dependsOn") or [])
    for aid, ds in deps.items():
        for d in ds:
            if d not in ids:
                raise ContractError(
                    f"action {aid}: dependsOn unknown action {d!r}")
    # cycle check (Kahn)
    indeg = {aid: 0 for aid in deps}
    for ds in deps.values():
        for d in ds:
            indeg[d] += 0  # d exists (checked above)
    for aid, ds in deps.items():
        indeg[aid] = len(ds)
    queue = [a for a, n in indeg.items() if n == 0]
    seen = 0
    rev: dict[str, list[str]] = {aid: [] for aid in deps}
    for aid, ds in deps.items():
        for d in ds:
            rev[d].append(aid)
    while queue:
        n = queue.pop()
        seen += 1
        for m in rev[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                queue.append(m)
    if seen != len(deps):
        raise ContractError("action dependency graph has a cycle")

    pre = p.get("preconditions")
    if not isinstance(pre, list) or not pre:
        raise ContractError("plan.preconditions must be a non-empty list")
    types = set()
    for pc in pre:
        if isinstance(pc, dict):
            _check_plan_keys(pc, PLAN_PRECONDITION_KEYS, "precondition",
                             "a precondition is a gate; a key nothing reads is a "
                             "gate nothing applies")
        t = pc.get("type") if isinstance(pc, dict) else None
        if t not in PRECONDITION_TYPES:
            raise ContractError(f"unknown precondition type: {t!r}")
        types.add(t)
    if "report-executable" not in types:
        raise ContractError(
            "preconditions must include report-executable — a plan that "
            "does not require verification to pass contradicts the thesis")

    # D177: witnessed capabilities are VERIFIED but not authored. Each must be
    # well-formed, have a pinned head (verified => read, D28), and be DISJOINT from
    # writes (a witness mutates nothing — being in writes would be a lie).
    witnessed = p.get("witnessed")
    if witnessed is not None:
        if not isinstance(witnessed, list):
            raise ContractError("plan.witnessed must be a list")
        writes_set = set(writes)
        for w in witnessed:
            if not isinstance(w, dict):
                raise ContractError("witnessed entry must be a mapping")
            cap = w.get("capability")
            if not cap:
                raise ContractError("witnessed entry missing capability")
            _check_plan_keys(w, PLAN_WITNESS_KEYS, f"witnessed {cap}",
                             "a witness record is the claim that something was "
                             "VERIFIED but not authored (D177); a key nothing "
                             "reads weakens that claim silently")
            for k in ("provider", "service", "reason"):
                if not w.get(k):
                    raise ContractError(f"witnessed {cap}: {k} is required")
            if cap not in heads:
                raise ContractError(
                    f"witnessed {cap} has no pinned head — a witnessed capability "
                    "is verified, so it must be read (D28)")
            if cap in writes_set:
                raise ContractError(
                    f"witnessed {cap} is also in plan.writes — a witness mutates "
                    "nothing (D177)")
    return doc
