"""State Model v0 — ledger event loading (spec/state-model.md, D35).

Fail-closed (D19): unknown event types, missing envelope fields and
unquoted timestamps are refused at load. Event identity is the hash of
the RAW canonical tree — no semantic normalization (D35).
"""
from __future__ import annotations
from typing import Any


from .yamlcompat import safe_load as _core12_load

from .contract import ContractError, read_document

# D1159: the OTHER closed set a ledger event carries. Published in
# `spec/state.schema.json`, branched on by the compiler (an observation
# sourced `candidate-declared` is adopt-recorded INTENT, carried as
# unverifiable rather than compared as measured reality) — and enforced
# nowhere until now, so a typo promoted intent into evidence.
OBSERVATION_SOURCES = {
    "provider-api",        # read from the provider's own API
    "probe",               # measured by an outcome probe (D59)
    "reachability",        # measured at the public edge
    "manual",              # supplied by a human, provenance carried
    "candidate-declared",  # adopt recorded the candidate's intent (F-LC3)
}

EVENT_TYPES = {
    "contract.published", "candidate.verified", "plan.sealed",
    "apply.started", "apply.finished", "apply.failed",
    "observation.recorded", "violation.detected", "violation.resolved",
    "probe.failed", "observation.failed",
    "binding.updated",
    "lease.acquired", "lease.renewed", "lease.released", "lease.broken",
    "operation.receipt",
    # D140: takeover authorship stamp.
    "ownership.claimed",
    # D229: converge lifecycle markers — run-scoped, lease-free, neither
    # mutations nor decisions. They let status/wait speak the converge tree.
    "converge.started", "converge.phase.entered",
    "converge.finished", "converge.failed",
}
ACTOR_TYPES = {"human", "agent", "runtime"}


def load_event(path: str) -> dict[str, Any]:
    return validate_event(_core12_load(read_document(path)))


def validate_event(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise ContractError("event document is empty or not a mapping")
    if doc.get("kind") != "LedgerEvent":
        raise ContractError("kind must be LedgerEvent")
    if doc.get("apiVersion") != "state/v0":
        raise ContractError("apiVersion must be state/v0")
    ev = doc.get("event")
    if not isinstance(ev, dict):
        raise ContractError("event block is required")
    etype = ev.get("type")
    if etype not in EVENT_TYPES:
        raise ContractError(f"unknown event type: {etype!r}")
    caps = ev.get("capabilities")
    if not isinstance(caps, list) or not caps \
            or not all(isinstance(c, str) for c in caps):
        raise ContractError("event.capabilities must be a non-empty list of ids")
    occurred = ev.get("occurredAt")
    if not isinstance(occurred, str):
        raise ContractError(
            "event.occurredAt must be a quoted RFC3339 string "
            "(unquoted YAML timestamps are not canonicalizable)")
    actor = ev.get("actor")
    if not isinstance(actor, dict) or not actor.get("id") \
            or actor.get("type") not in ACTOR_TYPES:
        raise ContractError(
            "event.actor must carry id and type (human|agent|runtime)")
    token = ev.get("fencingToken")
    if token is not None and (isinstance(token, bool)
                              or not isinstance(token, int) or token < 1):
        raise ContractError("event.fencingToken must be a positive integer")
    sig = doc.get("sig")
    if sig is not None:
        _validate_sig(sig)
    if etype == "observation.recorded":
        body = ev.get("body")
        obs = body.get("observations") if isinstance(body, dict) else None
        for o in obs or []:
            if not isinstance(o, dict):
                continue
            src = o.get("source")
            if src not in OBSERVATION_SOURCES:
                raise ContractError(f"unknown observation source: {src!r}")
    return doc


def _is_hex(s: Any, width: int) -> bool:
    # lowercase only: one spelling, one hash, no aliasing
    if not isinstance(s, str) or len(s) != width or s != s.lower():
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def _is_event_hash(s: Any) -> bool:
    return isinstance(s, str) and s.startswith("sha256:") \
        and _is_hex(s[len("sha256:"):], 64)


def _validate_sig(sig: Any) -> None:
    """D102/D134: when present, the detached signature envelope must be
    well-formed — a truncated signature or a missing ledger claim is
    refused at load, not carried. Lowercase hex only. The envelope is
    excluded from the event hash (see canonical)."""
    if not isinstance(sig, dict) or sig.get("alg") != "ed25519" \
            or not _is_hex(sig.get("pub"), 64) \
            or not _is_hex(sig.get("sig"), 128) \
            or not _is_event_hash(sig.get("ledger")):
        raise ContractError(
            "sig must be an ed25519 envelope: "
            "{alg: ed25519, pub: 32-byte hex, sig: 64-byte hex, "
            "ledger: sha256:<64 hex> (the genesis event's hash, D134)}")
