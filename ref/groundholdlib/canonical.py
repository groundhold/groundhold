"""Canonicalization and hashing (D34, spec/canonicalization.md).

Identity is the sha256 of domain-separated canonical JSON of the parsed
semantic model — never of source bytes. All numbers render as strings
(NUMSTR) so that two implementations produce byte-identical hashes.
"""
from __future__ import annotations
import hashlib
from typing import Any

from . import scalars
from .contract import Contract, Candidate, Constraint, ContractError

DOMAINS = {
    "contract": "groundhold/canon/v1:contract",
    "candidate": "groundhold/canon/v1:candidate",
    "event": "groundhold/canon/v1:event",
    "plan": "groundhold/canon/v1:plan",
    "discovery": "groundhold/canon/v1:discovery",
}


# Largest integer an IEEE-754 double represents exactly (2^53). Beyond
# it a JSON round-trip is lossy, so a canonical document may not carry
# such an integer as a NUMBER (D66) — both implementations refuse it
# identically; use a string for bigger integers.
_MAX_SAFE_INTEGER = 2 ** 53


def _num_str(v: Any) -> str:
    """Shared NUMSTR rule (D66): identical output in Python and Go,
    stable across a JSON round-trip. An integer that arrived AS an int
    is checked WITHOUT float() (no silent >2^53 rounding); a float is
    checked as a double."""
    if isinstance(v, bool):  # bool is an int subclass — never a number
        raise ContractError(f"cannot canonicalize bool as number: {v!r}")
    if isinstance(v, int):
        if v >= _MAX_SAFE_INTEGER or v <= -_MAX_SAFE_INTEGER:
            raise ContractError(
                f"integer {v} exceeds the JSON-safe range (2^53); "
                "encode it as a string to canonicalize")
        return str(v)
    f = float(v)
    if f != f or f in (float("inf"), float("-inf")):
        raise ContractError(f"cannot canonicalize non-finite number: {v!r}")
    if f == int(f):
        if abs(f) >= _MAX_SAFE_INTEGER:
            raise ContractError(
                f"integer {f:.0f} exceeds the JSON-safe range (2^53); "
                "encode it as a string to canonicalize")
        return str(int(f))
    for p in range(1, 18):
        s = f"{f:.{p}f}"
        if float(s) == f:
            return s
    # A non-integral magnitude too small to round-trip in fixed-point (|f| below
    # ~1e-17) would otherwise fall to a lossy "0.000…0" — a FALSE canonical form
    # that collides every such value onto one string (1e-18 and 1e-20 hash
    # identically), forging a shared identity. Refuse, exactly as >2^53 does: the
    # canonicalizer stays injective. Encode tiny values as strings.
    raise ContractError(
        f"number {f!r} is too small to canonicalize as a fixed-point decimal "
        "without loss (magnitude below ~1e-17); encode it as a string")


def _quote(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canon(v: Any) -> str:
    """Canonical JSON: sorted keys, no whitespace, numbers as NUMSTR
    strings, minimal escaping."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return '"' + _num_str(v) + '"'
    if isinstance(v, str):
        return _quote(v)
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: str(kv[0]))
        return ("{" + ",".join(_quote(str(k)) + ":" + canon(x)
                               for k, x in items) + "}")
    raise ContractError(f"cannot canonicalize value of type {type(v).__name__}")


def _scalar_model(s: scalars.Scalar) -> dict:
    k = s.kind
    if k == "duration":
        return {"kind": k, "ms": s.value}
    if k == "money":
        return {"kind": k, "amount": s.value[0], "currency": s.value[1]}
    if k == "percent":
        return {"kind": k, "value": s.value}
    if k == "bytes":
        return {"kind": k, "bytes": s.value}
    if k == "protocol":
        name, major, minor, patch = s.value
        return {"kind": k, "name": name,
                "major": major, "minor": minor, "patch": patch}
    if k == "list":
        return {"kind": k, "items": [_scalar_model(x) for x in s.value]}
    return {"kind": k, "value": s.value}  # bool | number | string


def _constraint_model(c: Constraint) -> dict:
    m: dict = {"id": c.id, "severity": c.severity, "verify": c.verify_method}
    if c.subject:
        m["subject"] = c.subject
    if c.path:
        m["path"] = c.path
    if c.op:
        m["op"] = c.op
    if c.objective:
        m["objective"] = c.objective
    if c.expected is not None:
        m["value"] = _scalar_model(c.expected)
    return m


def contract_model(c: Contract) -> dict:
    m: dict = {
        "apiVersion": "contract/v0.1",
        "kind": "InfrastructureContract",
        "id": c.id,
        "version": c.version,
        "capabilities": [
            {"id": cid, "type": cap["type"],
             **({"state": "retired"} if cap.get("state") == "retired" else {})}
            for cid, cap in sorted(c.capabilities.items())],
        "constraints": [_constraint_model(x)
                        for x in sorted(c.constraints, key=lambda k: k.id)],
    }
    if c.environment:
        m["environment"] = c.environment
    if c.assumptions:
        fixed = []
        for a in c.assumptions:
            a2 = dict(a)
            if a2.get("affects"):
                a2["affects"] = sorted(a2["affects"])
            fixed.append(a2)
        m["assumptions"] = sorted(fixed, key=lambda a: a.get("id") or "")
    if c.outcomes:
        m["outcomes"] = sorted(c.outcomes, key=lambda o: o.get("id") or "")
    if c.autonomy:
        m["autonomy"] = c.autonomy
    return m


def candidate_model(cand: Candidate) -> dict:
    caps = []
    for cid in sorted(cand.capabilities):
        attrs = cand.capabilities[cid]
        entry: dict = {"id": cid, "attributes": []}
        for p in sorted(attrs):
            pv = attrs[p]
            am: dict = {"path": p, "status": pv.status}
            if pv.scalar is not None:
                am["value"] = _scalar_model(pv.scalar)
            if pv.source:
                am["source"] = pv.source
            if pv.confidence is not None:
                am["confidence"] = pv.confidence
            entry["attributes"].append(am)
        for k, v in (cand.extras.get(cid) or {}).items():
            entry[k] = v
        caps.append(entry)
    return {
        "apiVersion": "candidate/v0.1",
        "kind": "ImplementationCandidate",
        "contract": cand.contract_id,
        "capabilities": caps,
    }


def _hash(domain: str, model: dict) -> str:
    data = (DOMAINS[domain] + "\n" + canon(model)).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_contract(c: Contract) -> str:
    return _hash("contract", contract_model(c))


def hash_candidate(cand: Candidate) -> str:
    return _hash("candidate", candidate_model(cand))


def hash_event(doc: dict) -> str:
    """D35: event identity is the raw canonical tree — an event records
    what was said; normalizing history would falsify it.
    D102: the top-level `sig` key is EXCLUDED — a signature attests the
    identity, it is not part of it (detached-signature rule), so signed
    and unsigned copies of the same event share one hash."""
    if "sig" in doc:
        doc = {k: v for k, v in doc.items() if k != "sig"}
    return _hash("event", doc)


def hash_plan(doc: dict) -> str:
    """D36: a sealed plan records a decision (raw tree, like events) —
    normalizing it would re-open it."""
    return _hash("plan", doc)


def hash_discovery(doc: dict) -> str:
    """D52: a discovery document records what enumeration SAW (raw
    tree, like events); drafts cite it as their provenance root."""
    return _hash("discovery", doc)
