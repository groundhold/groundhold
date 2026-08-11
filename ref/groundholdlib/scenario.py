"""Deterministic concurrency scenario engine (D37).

Pins the ledger/lease/fencing semantics of D28-D29: CAS appends, lease
tokens derived from history, fencing rejection of stale workers, receipt
reconciliation before lease-break. A logical clock replaces wall time;
concurrency is modeled as interleaved steps — fully deterministic, no
threads, no network (verifier invariant 6 holds).

Step forms:
  {tick: N}
  {append: {type, capabilities, actor?, actorType?, body?, fencingToken?},
   expectedHeads?: {cap: genesis | "@N"}}      # "@N" = hash of step N's event
  {checkHeads: {cap: genesis | "@N"}}

Results per step:
  tick        -> {status: ok}
  append      -> {status: ok | conflict | rejected} (+ token for lease.acquired)
  checkHeads  -> {status: fresh | stale}

conflict = CAS mismatch (the mechanism working, not an error);
rejected  = rule violation (missing lease, stale fencing token, ...).
"""
from __future__ import annotations
import datetime
from typing import Any

from . import canonical
from .contract import ContractError
from .state import validate_event

MUTATION_TYPES = {"binding.updated", "apply.started", "apply.finished",
                  "apply.failed"}
# D41: decision events advance the decision heads that sealed plans pin;
# knowledge (observations, violations, receipts) and coordination
# (leases) are audit-chained but decision-head-neutral
DECISION_TYPES = MUTATION_TYPES | {"contract.published",
                                   "candidate.verified", "plan.sealed"}
RECEIPT_STATUSES = {"pending", "succeeded", "failed", "unknown", "retryable"}


def _ts(clock: int) -> str:
    return datetime.datetime.fromtimestamp(
        clock, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve(ref: Any, step_hashes: dict[int, str]) -> Any:
    if isinstance(ref, str) and ref.startswith("@"):
        try:
            idx = int(ref[1:])
        except ValueError:
            raise ContractError(f"bad step reference {ref!r}") from None
        if idx not in step_hashes:
            raise ContractError(f"reference {ref}: step has no event hash")
        return step_hashes[idx]
    return ref


def _active(lease: dict | None, clock: int) -> bool:
    return bool(lease) and not lease["ended"] and clock < lease["expiry"]


def run_scenario(doc: Any) -> list[dict]:
    if not isinstance(doc, dict) or doc.get("kind") != "ConcurrencyScenario":
        raise ContractError("kind must be ConcurrencyScenario")
    if doc.get("apiVersion") != "scenario/v0":
        raise ContractError("apiVersion must be scenario/v0")
    steps = doc.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ContractError("steps must be a non-empty list")
    env = doc.get("environment", "test")

    clock = 0
    heads: dict[str, str] = {}
    decision_heads: dict[str, str] = {}
    step_hashes: dict[int, str] = {}
    leases: dict[str, dict] = {}      # cap -> {token, expiry, ttl, ended, seq}
    max_token: dict[str, int] = {}
    # D633: a fold-time lease identity. Mirrors the Go runtime's leaseSeq; a dict so
    # the nested commit() closures can increment it.
    state: dict[str, int] = {"leaseSeq": 0}
    pending: dict[str, set] = {}      # cap -> operation ids
    results: list[dict] = []

    for idx, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise ContractError(f"step {idx}: not a mapping")

        if "tick" in step:
            n = step["tick"]
            # time only moves forward — a reversible clock would resurrect
            # expired leases and break fencing
            if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
                raise ContractError(
                    f"step {idx}: tick must be a positive integer")
            clock += n
            results.append({"status": "ok"})
            continue

        if "checkHeads" in step:
            want = {c: _resolve(h, step_hashes)
                    for c, h in step["checkHeads"].items()}
            cur = {c: heads.get(c, "genesis") for c in want}
            results.append({"status": "fresh" if cur == want else "stale"})
            continue

        if "checkDecisionHeads" in step:
            want = {c: _resolve(h, step_hashes)
                    for c, h in step["checkDecisionHeads"].items()}
            cur = {c: decision_heads.get(c, "genesis") for c in want}
            results.append({"status": "fresh" if cur == want else "stale"})
            continue

        if "append" not in step:
            raise ContractError(f"step {idx}: unknown step form")
        a = step["append"]
        caps = a.get("capabilities") or []
        ev: dict[str, Any] = {
            "type": a.get("type"),
            "environment": env,
            "capabilities": caps,
            "occurredAt": _ts(clock),
            "actor": {"id": a.get("actor", "runtime-1"),
                      "type": a.get("actorType", "runtime")},
            "prev": {c: heads.get(c, "genesis") for c in caps},
        }
        if "body" in a:
            ev["body"] = a["body"]
        if "fencingToken" in a:
            ev["fencingToken"] = a["fencingToken"]
        event_doc = {"apiVersion": "state/v0", "kind": "LedgerEvent",
                     "event": ev}
        validate_event(event_doc)  # malformed scenario = authoring error

        # 1. CAS (D28)
        exp = step.get("expectedHeads")
        if exp is not None:
            conflict = any(
                heads.get(c, "genesis") != _resolve(exp.get(c, "genesis"),
                                                    step_hashes)
                for c in caps)
            if conflict:
                results.append({"status": "conflict"})
                continue

        # 2. rules (D29)
        rejected, extras, commit = _check_rules(
            ev, a, caps, clock, leases, max_token, pending, state)
        if rejected is not None:
            results.append(rejected)
            continue

        # 3. commit
        commit()
        h = canonical.hash_event(event_doc)
        for c in caps:
            heads[c] = h
            if ev["type"] in DECISION_TYPES:
                decision_heads[c] = h
        step_hashes[idx] = h
        results.append({"status": "ok", **extras})

    return results


def _check_rules(ev, a, caps, clock, leases, max_token, pending, state):
    """Returns (rejected_result | None, ok_extras, commit_fn)."""
    etype = ev["type"]
    body = a.get("body") or {}
    noop = lambda: None  # noqa: E731

    def reject(reason):
        return ({"status": "rejected", "reason": reason}, {}, noop)

    if etype == "lease.acquired":
        ttl = body.get("ttlSeconds")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
            return reject("lease.acquired requires body.ttlSeconds > 0")
        for c in caps:
            if _active(leases.get(c), clock):
                return reject(f"active lease exists on {c}")
        token = max((max_token.get(c, 0) for c in caps), default=0) + 1

        def commit():
            state["leaseSeq"] += 1
            for c in caps:
                leases[c] = {"token": token, "expiry": clock + ttl,
                             "ttl": ttl, "ended": False, "seq": state["leaseSeq"]}
                max_token[c] = token
        return (None, {"token": token}, commit)

    if etype in ("lease.released", "lease.renewed"):
        tok = ev.get("fencingToken")
        for c in caps:
            lease = leases.get(c)
            if not (_active(lease, clock) and lease["token"] == tok):
                return reject(f"no active lease with token {tok!r} on {c}")

        def commit():
            for c in caps:
                if etype == "lease.released":
                    leases[c]["ended"] = True
                else:
                    ttl = body.get("ttlSeconds", leases[c]["ttl"])
                    leases[c]["expiry"] = clock + ttl
                    leases[c]["ttl"] = ttl
        return (None, {}, commit)

    if etype == "lease.broken":
        adopt = bool(body.get("adoptReceipts"))
        for c in caps:
            if pending.get(c) and not adopt:
                return reject(
                    f"pending operation receipts on {c} — reconcile first (D29)")

        def commit():
            for c in caps:
                if c in leases:
                    leases[c]["ended"] = True
                if adopt:
                    pending[c] = set()
        return (None, {}, commit)

    if etype in MUTATION_TYPES:
        tok = ev.get("fencingToken")
        if tok is None:
            return reject("mutation requires a fencing token (D29)")
        # D633: ONE lease must cover the whole affected set. Tokens are per-capability
        # counters, so two leases over disjoint capabilities both get token 1 — and a
        # per-capability token check then let a holder of {a,b} mutate {b,c} the moment
        # someone else acquired {c}. `seq` is a fold-time lease identity: recomputed on
        # every replay, never on the wire, and it leaves token arithmetic untouched.
        covering = None
        for c in caps:
            lease = leases.get(c)
            if not (_active(lease, clock) and lease["token"] == tok):
                return reject(f"stale or missing fencing token on {c}")
            if covering is None:
                covering = lease["seq"]
            elif lease["seq"] != covering:
                return reject(
                    f"the affected capabilities are held by DIFFERENT leases — {c} is "
                    "under another lease that happens to carry the same token number; "
                    "one mutation must be covered by ONE lease (D29)")
        return (None, {}, noop)

    if etype == "operation.receipt":
        op = body.get("operationId")
        status = body.get("status")
        if not op or status not in RECEIPT_STATUSES:
            return reject("receipt requires operationId and a valid status")

        def commit():
            for c in caps:
                if status in ("pending", "unknown"):
                    # unknown is NONTERMINAL (D57): the operation stays
                    # pending until resume concludes it — treating it
                    # as neither pending nor terminal let lease.broken
                    # slip past D29 (caught by the n=200 differential)
                    pending.setdefault(c, set()).add(op)
                elif status in ("succeeded", "failed", "retryable"):
                    # D241: retryable concludes a throttled intent that did not
                    # land — clears pending, like succeeded/failed.
                    pending.get(c, set()).discard(op)
        return (None, {}, commit)

    # contract.published, candidate.verified, plan.sealed,
    # observation.recorded, violation.detected: no extra rules
    return (None, {}, noop)
