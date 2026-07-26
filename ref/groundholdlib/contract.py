"""Loading + structural validation of Contract and ImplementationCandidate documents.

Every attribute value in a candidate may carry provenance:
    plain scalar                      -> status: declared (shorthand)
    {value, status, source, confidence} -> explicit provenance
Statuses: declared | inferred | assumed | unknown
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
import yaml

from .yamlcompat import safe_load as _core12_load

from . import scalars

VALID_STATUSES = {"declared", "inferred", "assumed", "unknown"}
VALID_SEVERITIES = {"hard", "soft"}
VALID_METHODS = {"static", "provider-api", "probe"}
VALID_OPS = set(scalars.OPERATORS) | scalars.PRESENCE_OPERATORS

CAPABILITY_TYPES_V01 = {
    "capability.database.relational",
    "capability.storage.object",
    "capability.network.private",
    "capability.workload.container",
    "capability.function.serverless",
    "capability.identity.sso",
    "capability.identity.oauth-client",
    "capability.messaging.queue",
    "capability.messaging.topic",
    "capability.secret",
    "capability.cache.keyvalue",
    "capability.dns.zone",
    "capability.dns.record",
    "capability.authorization.grant",
    "capability.authorization.role",
    "capability.compute.quota",
    "capability.cluster.namespace",
    "capability.gitops.application",
    "capability.cluster.kubernetes",
    "capability.email.sending",
    "capability.ai.inference",
    "capability.ai.speech",
    "capability.compute.instance",
    "capability.storage.block",
    "capability.compute.image",
    "capability.compute.autoscaling",
    "capability.cost.budget",
    "capability.cluster.addon",
    "capability.identity.podidentity",
    "capability.observability.changefeed",
    "capability.network.loadbalancer",
    "capability.monitoring.alert",
    "capability.monitoring.dashboard",
    "capability.monitoring.uptime",
    "capability.monitoring.logmetric",
    "capability.registry.image",
    "capability.storage.filesystem",
    "capability.database.nosql",
    "capability.search.index",
    "capability.streaming.pipe",
    "capability.messaging.kafka",
    "capability.security.waf",
    "capability.certificate.tls",
    "capability.cdn.distribution",
    "capability.apigateway.http",
    "capability.container.job",
    "capability.identity.serviceaccount",
    "capability.warehouse.analytics",
    "capability.scheduler.cron",
    "capability.key.encryption",
    "capability.vpn.gateway",
    "capability.backup.vault",
    "capability.backup.plan",
    "capability.audit.trail",
    "capability.email.inbound",
    "capability.security.threatdetection",
    "capability.monitoring.logs",
}


class ContractError(Exception):
    pass


# Defends against oversized documents. YAML alias-expansion bombs remain a
# known residual risk of the Python reference; the Go runtime's parser has
# built-in expansion limits.
MAX_DOCUMENT_BYTES = 1 << 20


def read_document(path: str) -> str:
    with open(path) as f:
        data = f.read(MAX_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ContractError(f"document exceeds {MAX_DOCUMENT_BYTES} bytes")
    return data


@dataclass
class Provenanced:
    scalar: scalars.Scalar | None   # None only when status == unknown
    status: str = "declared"
    source: str | None = None
    confidence: float | None = None


@dataclass
class Constraint:
    id: str
    subject: str
    path: str | None
    op: str | None
    value: Any
    severity: str
    verify_method: str
    objective: str | None = None       # minimize | maximize (soft only)
    expected: scalars.Scalar | None = None  # D19: value parsed at load


@dataclass
class Contract:
    id: str
    environment: str
    version: int
    capabilities: dict[str, dict]                  # id -> {type, requirements}
    constraints: list[Constraint] = field(default_factory=list)
    assumptions: list[dict] = field(default_factory=list)
    outcomes: list[dict] = field(default_factory=list)
    autonomy: dict = field(default_factory=dict)


@dataclass
class Candidate:
    contract_id: str
    capabilities: dict[str, dict[str, Provenanced]]  # cap id -> path -> value
    extras: dict[str, dict] = field(default_factory=dict)
    # ^ cap id -> non-attribute keys (provider, service, implementation);
    #   ignored by the verifier, part of candidate identity (D26, D34)


def _provenanced(v: Any) -> Provenanced:
    if isinstance(v, dict) and "status" in v:
        status = v["status"]
        if status not in VALID_STATUSES:
            raise ContractError(f"invalid provenance status: {status}")
        raw = v.get("value")
        sc = None if raw is None else scalars.parse(raw)
        if sc is None and status != "unknown":
            raise ContractError(f"status {status} requires a value")
        conf = v.get("confidence")
        if conf is not None and (isinstance(conf, bool)
                                 or not isinstance(conf, (int, float))
                                 or not 0 <= conf <= 1):
            raise ContractError(f"confidence must be a number in [0,1]: {conf!r}")
        return Provenanced(sc, status, v.get("source"), conf)
    return Provenanced(scalars.parse(v))


def _id_clean(s: str) -> bool:
    """Reject control characters (incl. NUL) in a stable id. A NUL would let two
    distinct (capability, constraint) pairs collide in the "\\x00"-delimited
    violation-state key (D179 review), forging a shared snapshot identity."""
    return all(ord(c) >= 0x20 and ord(c) != 0x7f for c in s)


def _constraint(raw: dict, severity: str, idx: int) -> Constraint:
    cid = raw.get("id")
    if not cid:
        raise ContractError(f"{severity} constraint #{idx} missing id")
    if not _id_clean(cid):
        raise ContractError(f"constraint id {cid!r} contains a control character")
    if severity not in VALID_SEVERITIES:
        # fail-closed (D19): an unrecognized severity would silently
        # bypass the hard gate if allowed through
        raise ContractError(f"{cid}: invalid severity {severity!r}")
    op = raw.get("op")
    objective = raw.get("objective")
    if objective:
        if objective not in ("minimize", "maximize"):
            raise ContractError(f"{cid}: invalid objective {objective!r}")
        if severity == "hard":
            raise ContractError(f"{cid}: objectives are only valid on soft constraints")
        if op is not None or "value" in raw:
            raise ContractError(f"{cid}: objective is mutually exclusive with op/value")
    else:
        if op not in VALID_OPS:
            raise ContractError(f"{cid}: unknown operator {op!r}")
        if op not in scalars.PRESENCE_OPERATORS and "value" not in raw:
            raise ContractError(f"{cid}: operator {op} requires a value")
    # D19: parse the value now — an ill-typed value in the contract itself
    # is a load error, never a runtime unverifiable
    expected = None
    if not objective and op not in scalars.PRESENCE_OPERATORS:
        try:
            expected = scalars.parse(raw["value"])
        except scalars.TypeMismatch as e:
            raise ContractError(f"{cid}: ill-typed value: {e}") from e
        if op in ("in", "not-in", "subset-of") and expected.kind != "list":
            raise ContractError(f"{cid}: operator {op} requires a list value")
        if op == "compatible-with" and expected.kind != "protocol":
            raise ContractError(
                f"{cid}: operator {op} requires a protocol value")
        if op in ("lte", "gte") and expected.kind not in scalars.ORDERABLE_KINDS:
            raise ContractError(
                f"{cid}: {expected.kind} value is not orderable")
    verify = (raw.get("verify") or {}).get("method", "static")
    if verify not in VALID_METHODS:
        raise ContractError(f"{cid}: unknown verify method {verify!r}")
    return Constraint(
        id=cid, subject=raw.get("subject", ""), path=raw.get("path"),
        op=op, value=raw.get("value"), severity=severity,
        verify_method=verify, objective=objective, expected=expected,
    )


def load_contract(path: str) -> Contract:
    doc = _core12_load(read_document(path))
    if not isinstance(doc, dict):
        raise ContractError("contract document is empty or not a mapping")
    _check_safe_numbers(doc)
    if doc.get("kind") != "InfrastructureContract":
        raise ContractError("kind must be InfrastructureContract")
    if doc.get("apiVersion") != "contract/v0.1":
        raise ContractError("apiVersion must be contract/v0.1")
    meta = doc.get("meta") or {}
    if not meta.get("id"):
        raise ContractError("meta.id is required")

    caps: dict[str, dict] = {}
    retired: set[str] = set()
    for cap in doc.get("capabilities") or []:
        if not cap.get("id"):
            raise ContractError("capability missing id")
        if not _id_clean(cap["id"]):
            raise ContractError(
                f"capability id {cap['id']!r} contains a control character")
        if cap["id"] in caps:
            raise ContractError(f"duplicate capability id: {cap['id']}")
        if cap.get("type") not in CAPABILITY_TYPES_V01:
            raise ContractError(f"unknown capability type: {cap.get('type')}")
        state = cap.get("state", "active")
        if state not in ("active", "retired"):
            raise ContractError(f"{cap['id']}: invalid state {state!r}")
        if state == "retired":
            # D47: retirement is explicit, never absence — and a retired
            # capability with requirements is a contradiction
            if cap.get("requirements"):
                raise ContractError(
                    f"{cap['id']}: retired capability cannot carry requirements")
            retired.add(cap["id"])
        caps[cap["id"]] = cap

    constraints: list[Constraint] = []
    cblock = doc.get("constraints") or {}
    for i, raw in enumerate(cblock.get("hard") or []):
        constraints.append(_constraint(raw, "hard", i))
    for i, raw in enumerate(cblock.get("soft") or []):
        constraints.append(_constraint(raw, "soft", i))
    for i, raw in enumerate(doc.get("budget") or []):
        raw.setdefault("severity", "hard")
        constraints.append(_constraint(raw, raw["severity"], i))

    # capability.requirements are sugar for hard constraints on that
    # capability; paths sort for deterministic constraint order across
    # implementations
    for cap_id, cap in caps.items():
        for j, (rpath, spec) in enumerate(
                sorted((cap.get("requirements") or {}).items())):
            constraints.append(_constraint(
                {"id": f"req-{cap_id}-{rpath}", "subject": cap_id, "path": rpath,
                 "op": spec.get("op", "equals"), "value": spec.get("value"),
                 "verify": {"method": "static"}},
                "hard", j))

    ids = [c.id for c in constraints]
    dupes = [x for x, n in Counter(ids).items() if n > 1]
    if dupes:
        raise ContractError(f"duplicate constraint ids: {sorted(dupes)}")
    for c in constraints:
        if c.subject and c.subject not in caps:
            raise ContractError(f"{c.id}: unknown subject {c.subject!r}")
        if c.subject in retired:
            raise ContractError(
                f"{c.id}: constraint targets retired capability {c.subject!r}")

    # D11 + D19: every reference between stable ids must resolve at load
    cids = set(ids)
    for a in doc.get("assumptions") or []:
        aid = a.get("id")
        if not aid:
            raise ContractError("assumption missing id")
        if a.get("status") not in VALID_STATUSES:
            raise ContractError(
                f"assumption {aid}: invalid status {a.get('status')!r}")
        conf = a.get("confidence")
        if conf is not None and (isinstance(conf, bool)
                                 or not isinstance(conf, (int, float))
                                 or not 0 <= conf <= 1):
            raise ContractError(
                f"assumption {aid}: confidence must be a number in [0,1]")
        for ref in a.get("affects") or []:
            if ref not in cids:
                raise ContractError(
                    f"assumption {aid}: affects unknown constraint {ref!r}")
    for entry in (doc.get("autonomy") or {}).get("forbidden") or []:
        if isinstance(entry, dict) and "disable" in entry \
                and entry["disable"] not in cids:
            raise ContractError(
                f"autonomy.forbidden: disable references "
                f"unknown constraint {entry['disable']!r}")
    for ref in (doc.get("autonomy") or {}).get("allow_replace_stateful") or []:
        if ref not in caps:
            raise ContractError(
                f"autonomy.allow_replace_stateful references "
                f"unknown capability {ref!r}")
    # D195: a malformed knob must not silently disarm the gate.
    _autonomy = doc.get("autonomy") or {}
    if "no_assumed_hard_basis" in _autonomy \
            and not isinstance(_autonomy["no_assumed_hard_basis"], bool):
        raise ContractError("autonomy.no_assumed_hard_basis must be a boolean")

    return Contract(
        id=meta["id"], environment=meta.get("environment", ""),
        version=int(meta.get("version", 1)), capabilities=caps,
        constraints=constraints, assumptions=doc.get("assumptions") or [],
        outcomes=doc.get("outcomes") or [], autonomy=doc.get("autonomy") or {},
    )


def _check_safe_numbers(v):
    """D66: refuse any raw integer outside the JSON-safe range (2^53)
    anywhere in a decoded document; a non-canonicalizable document is a
    structural error, never a verdict. Strings are untouched."""
    _MAX = 2 ** 53
    if isinstance(v, bool):
        return
    if isinstance(v, int):
        if v >= _MAX or v <= -_MAX:
            raise ContractError(
                f"integer {v} exceeds the JSON-safe range (2^53); "
                "encode it as a string to canonicalize")
    elif isinstance(v, float):
        if v == int(v) and abs(v) >= _MAX:
            raise ContractError(
                f"integer {v:.0f} exceeds the JSON-safe range (2^53); "
                "encode it as a string to canonicalize")
    elif isinstance(v, dict):
        for x in v.values():
            _check_safe_numbers(x)
    elif isinstance(v, list):
        for x in v:
            _check_safe_numbers(x)


def load_candidate(path: str, contract: Contract | None = None,
                   vocabs: dict | None = None) -> Candidate:
    doc = _core12_load(read_document(path))
    _check_safe_numbers(doc)
    if not isinstance(doc, dict):
        raise ContractError("candidate document is empty or not a mapping")
    if doc.get("kind") != "ImplementationCandidate":
        raise ContractError("kind must be ImplementationCandidate")
    if doc.get("apiVersion") != "candidate/v0.1":
        raise ContractError("apiVersion must be candidate/v0.1")
    if not doc.get("contract"):
        raise ContractError("candidate must name its contract")
    caps: dict[str, dict[str, Provenanced]] = {}
    extras: dict[str, dict] = {}
    for cap_id, body in (doc.get("capabilities") or {}).items():
        attrs = {}
        for p, v in (body.get("attributes") or {}).items():
            try:
                attrs[p] = _provenanced(v)
            except scalars.TypeMismatch as e:
                raise ContractError(f"{cap_id}.{p}: {e}") from e
        caps[cap_id] = attrs
        extra = {k: v for k, v in body.items() if k != "attributes"}
        if extra:
            extras[cap_id] = extra
    cand = Candidate(contract_id=doc.get("contract", ""), capabilities=caps,
                     extras=extras)
    if contract is not None and vocabs:
        _vocab_check(cand, contract, vocabs)
    return cand


def _vocab_check(cand: Candidate, contract: Contract, vocabs: dict) -> None:
    """D23: values on vocabulary paths must match the declared kind (and
    enum, if any). Ill-typed authorship is refused at load (D19), before
    any constraint is evaluated. Paths outside the vocabulary are legal."""
    for cap_id, attrs in cand.capabilities.items():
        cap = contract.capabilities.get(cap_id)
        voc = vocabs.get(cap["type"]) if cap else None
        if voc is None:
            continue
        for p, pv in attrs.items():
            spec = voc.attributes.get(p)
            if not spec or pv.scalar is None:
                continue
            want = spec.get("kind")
            if want and pv.scalar.kind != want:
                raise ContractError(
                    f"{cap_id}.{p}: vocabulary defines kind {want}, "
                    f"got {pv.scalar.kind} ({pv.scalar.raw!r})")
            enum = spec.get("enum")
            if enum and pv.scalar.value not in enum:
                raise ContractError(
                    f"{cap_id}.{p}: {pv.scalar.raw!r} not in "
                    f"vocabulary enum {enum}")
