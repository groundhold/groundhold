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

from .yamlcompat import safe_load as _core12_load

from . import scalars

# D1160: the capability block's shape, CLOSED. `implementation` is the free-form
# half (D26); this level is structure, and a key the loader does not read here is a
# stated intent nothing will act on.
CANDIDATE_CAPABILITY_KEYS = {"attributes", "implementation", "provider", "service"}

VALID_STATUSES = {"declared", "inferred", "assumed", "unknown"}
VALID_SEVERITIES = {"hard", "soft"}
VALID_METHODS = {"static", "provider-api", "probe"}
# D728: the evidence ladder, so the loader can refuse an incoherent pair at load time.
_METHOD_RANK = {"static": 0, "provider-api": 1, "probe": 2}
VALID_OPS = set(scalars.OPERATORS) | scalars.PRESENCE_OPERATORS

def _edit_distance(a: str, b: str) -> int:
    """Levenshtein. Identical to the Go half — two implementations that suggest
    different things are two tools (D25, D719)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[j - 1] + 1, prev[j] + 1,
                           prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[len(b)]


def _nearest_types(want: str, known: list[str], n: int) -> list[str]:
    return [t for _, t in sorted((_edit_distance(want, k), k) for k in known)][:n]


def _unknown_type_message(unknown: list[str]) -> str:
    known = sorted(CAPABILITY_TYPES_V01)
    if len(unknown) == 1:
        parts = [f"unknown capability type: {unknown[0]}"]
    else:
        parts = [f"{len(unknown)} unknown capability types"]
    for u in unknown:
        if len(unknown) > 1:
            parts.append(f"  {u}")
        near = _nearest_types(u, known, 3)
        if near:
            parts.append("    closest known types: " + ", ".join(near))
    parts.append(f"  the vocabulary is closed and has {len(known)} types; "
                 "`groundhold explain <capability.type>` describes one")
    return "\n".join(parts)


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
    runtime_method: str = "static"
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
        _check_known_keys(v, PROVENANCED_KEYS, "a provenanced attribute",
                          "the provenance this loader does not read is dropped, and "
                          "the attribute keeps only what was spelled correctly")
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
        return Provenanced(sc, status,
                           _want_string(v, "source", "attribute source") or None,
                           conf)
    return Provenanced(scalars.parse(v))


def _id_clean(s: str) -> bool:
    """Reject control characters (incl. NUL) in a stable id. A NUL would let two
    distinct (capability, constraint) pairs collide in the "\\x00"-delimited
    violation-state key (D179 review), forging a shared snapshot identity."""
    return all(ord(c) >= 0x20 and ord(c) != 0x7f for c in s)


def _constraint(raw: dict, severity: str, idx: int) -> Constraint:
    cid = _want_string(raw, "id", "constraint id") or None
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
    vb = raw.get("verify") or {}
    _check_known_keys(vb, VERIFY_KEYS, f"{cid}: verify",
                      "a bar this loader cannot find is a bar nobody set, and the "
                      "default is the weakest evidence there is")
    verify = vb.get("method", "static")
    runtime = verify
    # D728: the two-bar form. `verify` compares the contract with the CANDIDATE, before
    # anything exists, so it can never hold provider evidence; `audit` judges recorded
    # reality, where provider evidence is the point. One field served both, so demanding
    # measurement made `verify` unpassable while accepting `static` let a hard security
    # constraint be satisfied by the document's own word.
    has_design, has_runtime = "design" in vb, "runtime" in vb
    if has_design or has_runtime:
        if "method" in vb:
            raise ContractError(
                f"{cid}: verify carries both `method` and `design`/`runtime` — one bar "
                "or two, never both spellings of the same thing")
        if not (has_design and has_runtime):
            raise ContractError(
                f"{cid}: the two-bar verify form needs BOTH `design` and `runtime` — "
                "half of it would leave the other bar to a default nobody wrote")
        verify, runtime = vb["design"], vb["runtime"]
        if not isinstance(verify, str) or not isinstance(runtime, str):
            raise ContractError(
                f"{cid}: verify.design and verify.runtime must be strings — a bar the "
                "loader cannot read must not fall back to the weakest evidence there is")
    if verify not in VALID_METHODS:
        raise ContractError(f"{cid}: unknown verify method {verify!r}")
    if runtime not in VALID_METHODS:
        raise ContractError(f"{cid}: unknown verify.runtime {runtime!r}")
    if _METHOD_RANK[verify] > _METHOD_RANK[runtime]:
        raise ContractError(
            f"{cid}: verify.design {verify!r} is stronger than verify.runtime "
            f"{runtime!r} — a constraint cannot demand more evidence before it ships "
            "than after")
    return Constraint(
        id=cid,
        subject=_want_string(raw, "subject", f"constraint {cid} subject"),
        path=_want_string(raw, "path", f"constraint {cid} path") or None,
        op=op, value=raw.get("value"), severity=severity,
        verify_method=verify, runtime_method=runtime, objective=objective,
        expected=expected,
    )


def _int_version(meta: dict) -> int:
    """D610: `meta.version` is an integer or the document is refused.

    This coerced (`int("7")` -> 7, `int(3.0)` -> 3) and raised a bare TypeError on a
    list, while the runtime silently defaulted to 1 for anything non-int. Two readings
    of the same declaration, neither of them what the author wrote.
    """
    if "version" not in meta:
        return 1
    v = meta["version"]
    if not isinstance(v, int) or isinstance(v, bool):
        raise ContractError(f"meta.version must be an integer, got {type(v).__name__}")
    return v



# D673: what a document of each kind MEANS. Nothing checked this, so a misspelled
# block was silently dropped — `constraint:` (singular) made a contract requiring
# encryption PROVE a candidate that refuses it, and the contract then hashed
# identically to one with no constraints. An `x-` prefix is the escape hatch for
# anchor blocks and tool metadata.
_KNOWN_TOP_LEVEL = {
    "InfrastructureContract": {
        "apiVersion", "kind", "meta", "capabilities", "constraints",
        # D1170: root `requirements` removed — requirements are a CAPABILITY's
        # short form (D8); a root block hashed identically to no block at all.
        "assumptions", "outcomes", "autonomy", "budget",
    },
    # D1170: `meta` was here and read by nobody — a candidate with a note and one
    # without hash IDENTICALLY, so it does not even reach the canonical form. Removed
    # rather than hashed: candidate identity is pinned by every sealed plan. `x-` is
    # the escape for a note, and the schema publishes exactly these four.
    "ImplementationCandidate": {
        "apiVersion", "kind", "contract", "capabilities",
    },
}


# D1161: the levels INSIDE a contract, closed for the same reason the top level is.
# `_check_top_level_keys` has taken the whole document since D673 and nothing else, so a
# stray key in a capability, in `meta` or in a provenanced attribute was read by nothing
# while the document still validated.
# D1162: the constraint object and its verify block. `verify` is guarded against every
# wrong VALUE and was blind to a wrong KEY — `method` defaults to "static", so `vrify:`
# or `methdo:` turned a constraint that must be proven against the provider into one
# proven by the candidate's own word, and the plan became executable.
# D1164: the consent blocks written as LISTS, named ONCE. The capability check below
# used a hand-typed tuple of THREE while the runtime read five, so a contract naming an
# unknown capability under `allow_field_reclaim` was refused by one implementation and
# accepted by the other — the divergence the comment there warns about, live.
AUTONOMY_LIST_KEYS = ("forbidden", "allow_replace_stateful", "allow_intrusive_probes",
                      "allow_protection_lift", "allow_field_reclaim",
                      "allow_emission_adopt")

# The whole block, CLOSED. D658 shape-gated these after a `forbidden` written as a
# MAPPING lost `delete_stateful` and a bound stateful database was destroyed at exit 0
# with validate reporting OK. A misspelled KEY does the identical thing.
AUTONOMY_KEYS = set(AUTONOMY_LIST_KEYS) | {"auto_execute", "no_assumed_hard_basis"}

# D1166: D8's short form, and exactly what the schema publishes for it. The sugar builds
# a hard constraint with a STATIC bar and reads nothing else, so a `verify:` written here
# was silently dropped — the same residency requirement is blocking as a constraint and
# satisfied as sugar, with no typo involved.
REQUIREMENT_KEYS = {"op", "value"}

# The record an assumption IS. NOT reserved like `outcomes`/`auto_execute` — it does what
# its name promises (it is written down, hashed, and `affects` is reference-checked); it
# just does not change a verdict. Closed because a misspelled `confidance` drops the
# number from the record, and a reader cannot tell that from "nobody stated one".
ASSUMPTION_KEYS = {"id", "statement", "status", "source", "confidence", "affects"}

CONSTRAINT_KEYS = {"id", "subject", "path", "op", "value", "verify"}
SOFT_CONSTRAINT_KEYS = CONSTRAINT_KEYS | {"objective"}
BUDGET_CONSTRAINT_KEYS = CONSTRAINT_KEYS | {"severity"}
VERIFY_KEYS = {"method", "design", "runtime"}

CONTRACT_CAPABILITY_KEYS = {"id", "type", "requirements", "state"}
CONTRACT_META_KEYS = {"id", "environment", "version", "owner"}
PROVENANCED_KEYS = {"status", "value", "source", "confidence"}


def _check_known_keys(doc: dict, known: set, where: str, why: str) -> None:
    unknown = sorted(k for k in doc
                     if k not in known and not str(k).startswith("x-"))
    if unknown:
        raise ContractError(
            f"{where} declares unknown key(s) {', '.join(unknown)} — {why}. "
            "Rename it, or prefix it with `x-` if it is deliberately not runtime data")


def _check_top_level_keys(doc: dict, kind: str) -> None:
    known = _KNOWN_TOP_LEVEL.get(kind)
    if known is None:
        return
    unknown = sorted(k for k in doc
                     if k not in known and not str(k).startswith("x-"))
    if unknown:
        # D1170: kind-specific example — a candidate has no `constraints` block.
        why = ("a misspelling of `constraints` proves a candidate that violates them"
               if kind != "ImplementationCandidate" else
               "a misspelled `capabilities` implements nothing, and the contract it "
               "claims to satisfy is verified against an empty document")
        raise ContractError(
            f"{kind} declares unknown top-level key(s) {', '.join(unknown)} — a "
            f"block this loader does not read is silently non-gating, and {why}. "
            "Rename it, or prefix it with `x-` if it is deliberately not runtime "
            "data")




def _want_list(m: dict, key: str, where: str) -> list:
    """D683: a block of the wrong shape is not an empty block. `assumptions` was
    gated and `outcomes` beside it was not, so a mis-shaped one was dropped and the
    contract hashed identically to one without it."""
    if key not in m or m[key] is None:
        return []
    v = m[key]
    if not isinstance(v, list):
        raise ContractError(
            f"{where} must be a list, got {type(v).__name__} — a block of the wrong "
            "shape is not an empty block, and reading it as one would silently drop "
            "everything in it")
    return v


def _want_string(m: dict, key: str, where: str) -> str:
    """D681: a non-string value for a string-typed field used to be canonicalized
    RAW here and dropped to "" in the Go runtime, so one document had two
    identities — each of them a DIFFERENT valid document's. The schema types these
    as strings; both implementations refuse."""
    if key not in m or m[key] is None:
        return ""
    v = m[key]
    if not isinstance(v, str):
        raise ContractError(
            f"{where} must be a string, got {type(v).__name__} ({v!r}) — a value "
            "of the wrong type is not an absent one, and dropping it silently "
            "gives this document the identity of a DIFFERENT one")
    return v


def load_contract(path: str) -> Contract:
    doc = _core12_load(read_document(path))
    if not isinstance(doc, dict):
        raise ContractError("contract document is empty or not a mapping")
    _check_safe_numbers(doc)
    if doc.get("kind") != "InfrastructureContract":
        raise ContractError("kind must be InfrastructureContract")
    if doc.get("apiVersion") != "contract/v0.1":
        raise ContractError("apiVersion must be contract/v0.1")
    _check_top_level_keys(doc, "InfrastructureContract")
    meta = doc.get("meta") or {}
    _check_known_keys(meta, CONTRACT_META_KEYS, "meta",
                      "a field this loader does not read carries no meaning into "
                      "the document")
    if not meta.get("id"):
        raise ContractError("meta.id is required")

    caps: dict[str, dict] = {}
    retired: set[str] = set()
    unknown_types: list[str] = []
    for cap in doc.get("capabilities") or []:
        _check_known_keys(cap, CONTRACT_CAPABILITY_KEYS, "a capability",
                          "a contract is where a REQUIREMENT is declared, so a key "
                          "nothing reads is a requirement that never existed")
        if not cap.get("id"):
            raise ContractError("capability missing id")
        if not _id_clean(cap["id"]):
            raise ContractError(
                f"capability id {cap['id']!r} contains a control character")
        if cap["id"] in caps:
            raise ContractError(f"duplicate capability id: {cap['id']}")
        if cap.get("type") not in CAPABILITY_TYPES_V01:
            # D719: collect, do not raise. Refusing at the FIRST unknown type made a
            # contract with two mistakes cost two runs to discover, and named what was
            # wrong without naming what is right over a CLOSED vocabulary this loader
            # is holding.
            unknown_types.append(str(cap.get("type")))
            continue
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
    if unknown_types:
        raise ContractError(_unknown_type_message(unknown_types))

    constraints: list[Constraint] = []
    cblock = doc.get("constraints") or {}
    why = ("a key this loader does not read cannot change what the constraint "
           "demands, and `verify` misspelled leaves the bar at its weakest default")
    for i, raw in enumerate(cblock.get("hard") or []):
        _check_known_keys(raw, CONSTRAINT_KEYS, "hard constraint", why)
        constraints.append(_constraint(raw, "hard", i))
    for i, raw in enumerate(cblock.get("soft") or []):
        _check_known_keys(raw, SOFT_CONSTRAINT_KEYS, "soft constraint", why)
        constraints.append(_constraint(raw, "soft", i))
    for i, raw in enumerate(doc.get("budget") or []):
        _check_known_keys(raw, BUDGET_CONSTRAINT_KEYS, "a budget constraint", why)
        raw.setdefault("severity", "hard")
        constraints.append(_constraint(raw, raw["severity"], i))

    # capability.requirements are sugar for hard constraints on that
    # capability; paths sort for deterministic constraint order across
    # implementations
    for cap_id, cap in caps.items():
        for j, (rpath, spec) in enumerate(
                sorted((cap.get("requirements") or {}).items())):
            _check_known_keys(
                spec, REQUIREMENT_KEYS,
                f"capabilities.{cap_id}.requirements.{rpath}",
                "this short form is STATIC-bar sugar (D8) and reads only `op` and "
                "`value` — a verification bar written here is dropped, so put the "
                "requirement under `constraints.hard` with its `verify:` instead")
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
        _check_known_keys(a, ASSUMPTION_KEYS, f"assumption {aid}",
                          "an assumption is a RECORD, and a key this loader does not "
                          "read is a part of it that will not be there when someone "
                          "reads it back")
        # D1157: `statement` is published as required and neither implementation read
        # it, so a shipped example carried assumptions with a `source` (where it came
        # from) and nothing saying WHAT was assumed. Blank counts as absent — spaces
        # satisfy the letter and record nothing.
        if not str(a.get("statement") or "").strip():
            raise ContractError(
                f"assumption {aid}: statement is required — `source` says where the "
                f"assumption came from, `statement` says what is assumed, and a "
                f"verdict's basis carries the latter")
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
    # D597 + D698: every consent list that names capabilities, from ONE list of keys.
    # The runtime learned this when `allow_intrusive_probes` turned out to be
    # unchecked — the list that SPENDS, since an intrusive probe restores a backup
    # into a scratch instance. The reference never learned it: it checked
    # `allow_replace_stateful` alone, so a typo in the other two loaded CLEAN here and
    # REFUSED in the runtime. A document one implementation accepts and the other
    # rejects breaks the dual guarantee as surely as a hash divergence does.
    for key in AUTONOMY_LIST_KEYS:
        if key == "forbidden":
            continue  # its entries are mappings, checked above
        for ref in (doc.get("autonomy") or {}).get(key) or []:
            if ref not in caps:
                raise ContractError(
                    f"autonomy.{key} references unknown capability {ref!r}")
    # D195: a malformed knob must not silently disarm the gate.
    _autonomy = doc.get("autonomy") or {}
    _check_known_keys(_autonomy, AUTONOMY_KEYS, "autonomy",
                      "every key here is a consent gate or a prohibition, and one this "
                      "loader does not read is a gate nobody armed")
    if "no_assumed_hard_basis" in _autonomy \
            and not isinstance(_autonomy["no_assumed_hard_basis"], bool):
        raise ContractError("autonomy.no_assumed_hard_basis must be a boolean")

    return Contract(
        id=_want_string(meta, "id", "meta.id"),
        environment=_want_string(meta, "environment", "meta.environment"),
        version=_int_version(meta), capabilities=caps,
        constraints=constraints, assumptions=doc.get("assumptions") or [],
        outcomes=_want_list(doc, "outcomes", "outcomes"),
        autonomy=doc.get("autonomy") or {},
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
    _check_top_level_keys(doc, "ImplementationCandidate")
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
        # D677: the identity is the key it is written under; a second one can only
        # disagree, and it used to overwrite the first in the canonical model.
        if "id" in body:
            raise ContractError(
                f"capabilities.{cap_id} carries an `id:` field — the capability's "
                "identity is the key it is written under, and a second one can only "
                "disagree with it")
        # D1160: the `id:` rule above, applied to the whole block. It was stated
        # there and enforced for one key, so every other stray key was collected
        # and dropped — an operand written one level too high sealed a plan at
        # exit 0 while the resource kept the default the author thought they had
        # changed. `implementation:` is the free-form half (D26); this level is
        # structure.
        for k in body:
            if k != "attributes" and k not in CANDIDATE_CAPABILITY_KEYS:
                raise ContractError(
                    f"capabilities.{cap_id} carries {k!r}, which is not one of the "
                    "four keys a capability block takes (attributes, implementation, "
                    "provider, service). If it is a driver operand, it belongs under "
                    "`implementation:` — written here it is read by nothing and "
                    "silently dropped")
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
            # D532: a list the vocabulary marks `unordered: true` is a SET, and a
            # set has no order. Canonicalize (sort) here, where the vocabulary is
            # known, so declared and observed compare equal everywhere without a
            # second meaning of equality. A plain `kind: list` stays an ordered
            # sequence (D21).
            if spec.get("unordered") and pv.scalar.kind == "list":
                _sort_scalar_list(pv.scalar)
            enum = spec.get("enum")
            if enum and pv.scalar.value not in enum:
                raise ContractError(
                    f"{cap_id}.{p}: {pv.scalar.raw!r} not in "
                    f"vocabulary enum {enum}")


def _sort_scalar_list(sc) -> None:
    """Canonicalize an unordered list in place by sorting on the canonical
    rendering of each element (D532). Raw follows value, or two spellings of one
    set would hash differently."""
    elems = sc.value
    if not isinstance(elems, list):
        return
    # The Scalar is frozen on purpose — a parsed value is not edited after the
    # fact. Sort the underlying lists IN PLACE instead of rebinding the fields.
    ordered = sorted(elems, key=lambda e: str(e.raw))
    raws = [e.raw for e in ordered]
    elems[:] = ordered
    if isinstance(sc.raw, list) and len(sc.raw) == len(raws):
        sc.raw[:] = raws
