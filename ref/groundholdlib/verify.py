"""Four-valued verification: satisfied | violated | unknown | unverifiable.

The engine never pretends. If it did not check something, the verdict says so:
  - verify.method is provider-api/probe  -> unknown (v0.1 evaluates static only)
  - attribute missing in the candidate   -> unknown
  - candidate value has status: unknown  -> unknown
  - type/unit mismatch                   -> unverifiable (contract or candidate is ill-typed)

A verdict based on an inferred/assumed value is still satisfied/violated,
but carries basis + confidence so downstream policy can gate on it.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict

from . import canonical, scalars
from .contract import Contract, Candidate, Constraint

SATISFIED, VIOLATED, UNKNOWN, UNVERIFIABLE = (
    "satisfied", "violated", "unknown", "unverifiable")


@dataclass
class Verdict:
    constraint: str
    severity: str
    verdict: str
    reason: str
    basis: str | None = None        # provenance status of the decisive value
    confidence: float | None = None
    observed: str | None = None
    pathInVocabulary: bool | None = None  # D23; None = no vocabulary provided
    # subject/path name what the verdict is ABOUT (additive, D91):
    # downstream projections join verdicts to observations by
    # (subject, path) instead of parsing prose
    subject: str = ""
    path: str = ""
    # verifyMethod names HOW the constraint can be proven (D94)
    verifyMethod: str = ""


def _eval(c: Constraint, cand: Candidate) -> Verdict:
    if c.objective:
        # objectives are scored by the planner, not gated by the verifier
        pv = cand.capabilities.get(c.subject, {}).get(c.path)
        if pv is None or pv.scalar is None or pv.status == "unknown":
            # D16: nothing observed -> nothing to score. Never claim satisfied.
            return Verdict(c.id, c.severity, UNKNOWN,
                           f"objective {c.objective} {c.path}: "
                           "not declared by the candidate",
                           basis=pv.status if pv else None)
        return Verdict(c.id, c.severity, SATISFIED,
                       f"objective {c.objective} {c.path} (scored, not gated)",
                       basis=pv.status, confidence=pv.confidence,
                       observed=repr(pv.scalar))

    if c.verify_method != "static":
        return Verdict(c.id, c.severity, UNKNOWN,
                       f"requires {c.verify_method} verification; "
                       "not evaluable from the candidate alone")

    attrs = cand.capabilities.get(c.subject)
    if attrs is None:
        return Verdict(c.id, c.severity, UNKNOWN,
                       f"candidate does not implement capability {c.subject!r}")

    present = c.path in attrs
    if c.op == "exists":
        return Verdict(c.id, c.severity, SATISFIED if present else VIOLATED,
                       f"path {c.path} {'present' if present else 'absent'}")
    if c.op == "absent":
        return Verdict(c.id, c.severity, VIOLATED if present else SATISFIED,
                       f"path {c.path} {'present' if present else 'absent'}")
    if not present:
        return Verdict(c.id, c.severity, UNKNOWN,
                       f"candidate does not declare {c.path}")

    pv = attrs[c.path]
    if pv.status == "unknown" or pv.scalar is None:
        return Verdict(c.id, c.severity, UNKNOWN,
                       f"candidate marks {c.path} as unknown",
                       basis="unknown", confidence=pv.confidence)

    try:
        # c.expected was parsed at load (D19); a TypeMismatch here is a
        # contract<->candidate disagreement, the last legitimate source
        # of unverifiable
        ok = scalars.OPERATORS[c.op](pv.scalar, c.expected)
    except scalars.TypeMismatch as e:
        return Verdict(c.id, c.severity, UNVERIFIABLE, str(e),
                       basis=pv.status, observed=repr(pv.scalar))

    return Verdict(
        c.id, c.severity,
        SATISFIED if ok else VIOLATED,
        f"{c.path} {c.op} {c.value!r}: observed {pv.scalar.raw!r}",
        basis=pv.status, confidence=pv.confidence,
        observed=repr(pv.scalar),
    )


def verify(contract: Contract, cand: Candidate,
           vocabs: dict | None = None) -> dict:
    def _path_flag(c: Constraint) -> bool | None:
        # D23: only claim vocabulary membership when a vocabulary exists
        # for the subject's capability type — never guess
        cap = contract.capabilities.get(c.subject)
        voc = vocabs.get(cap["type"]) if (vocabs and cap) else None
        if voc is None or not c.path:
            return None
        return c.path in voc.attributes

    verdicts = []
    for c in contract.constraints:
        v = _eval(c, cand)
        v.subject = c.subject
        v.path = c.path or ""
        v.verifyMethod = c.verify_method or ""
        v.pathInVocabulary = _path_flag(c)
        verdicts.append(v)

    hard = [v for v in verdicts if v.severity == "hard"]
    hard_violated = [v for v in hard if v.verdict == VIOLATED]
    hard_unknown = [v for v in hard if v.verdict in (UNKNOWN, UNVERIFIABLE)]
    assumed = [v for v in verdicts
               if v.verdict in (SATISFIED, VIOLATED) and v.basis in ("assumed", "inferred")]

    # D17: a candidate must name the contract it implements
    binding_errors = []
    if cand.contract_id != contract.id:
        binding_errors.append(
            f"candidate targets contract {cand.contract_id!r}, "
            f"not {contract.id!r}")

    executable = not binding_errors and not hard_violated and not hard_unknown
    return {
        "specVersion": "contract/v0.1",
        "contractHash": canonical.hash_contract(contract),
        "candidateHash": canonical.hash_candidate(cand),
        "contract": contract.id,
        "contractVersion": contract.version,
        "candidateFor": cand.contract_id,
        "summary": {
            "total": len(verdicts),
            "satisfied": sum(v.verdict == SATISFIED for v in verdicts),
            "violated": sum(v.verdict == VIOLATED for v in verdicts),
            "unknown": sum(v.verdict == UNKNOWN for v in verdicts),
            "unverifiable": sum(v.verdict == UNVERIFIABLE for v in verdicts),
            "verdictsOnAssumedValues": len(assumed),
        },
        "executable": executable,
        **({} if executable else {"code": "not-executable"}),
        "blockingReasons": (
            binding_errors
            + [f"hard constraint violated: {v.constraint}" for v in hard_violated]
            + [f"hard constraint not proven: {v.constraint} ({v.verdict})"
               for v in hard_unknown]
        ),
        "verdicts": [asdict(v) for v in verdicts],
    }
