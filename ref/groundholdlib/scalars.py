"""Typed scalars with units. Comparisons across incompatible types are refused,
not coerced — that refusal surfaces as an `unverifiable` verdict upstream.

Scalar kinds: duration | money | percent | bytes | protocol | bool | number | string | list
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any

class TypeMismatch(Exception):
    pass

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)(ms|s|m|h|d)$")
_DURATION_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}

_MONEY_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([A-Z]{3})$")
_PERCENT_RE = re.compile(r"^(\d+(?:\.\d+)?)%$")
# D15: KiB/MiB/GiB/TiB are 1024-based (IEC), KB/MB/GB/TB are 1000-based (SI)
_BYTES_RE = re.compile(r"^(\d+(?:\.\d+)?)(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)$")
_BYTES_MUL = {"B": 1,
              "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4,
              "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
# protocol/version, e.g. postgresql/16 or postgresql/16.4
_PROTO_RE = re.compile(r"^([a-z][a-z0-9\-]*)/(\d+)(?:\.(\d+))?(?:\.(\d+))?$")


@dataclass(frozen=True)
class Scalar:
    kind: str
    value: Any            # canonical: duration→ms, money→(amount, ccy), percent→float,
                          # bytes→int, protocol→(name, major, minor, patch)
    raw: Any = None

    def __repr__(self) -> str:
        return f"<{self.kind}:{self.raw if self.raw is not None else self.value}>"


def _fixed_point_round_trips(f: float) -> bool:
    """Whether f has a lossless fixed-point decimal form in the p in [1,17]
    scheme the canonicalizer uses (the same loop as _num_str)."""
    return any(float(f"{f:.{p}f}") == f for p in range(1, 18))


def _safe_num(f: float) -> None:
    """D66: a duration/byte value beyond the JSON-safe range cannot
    canonicalize deterministically — refuse it at parse (v0 limit)."""
    if f >= 2 ** 53 or f <= -(2 ** 53):
        raise TypeMismatch(
            f"value exceeds the JSON-safe range (2^53): {f:.0f}")
    # Lower bound, mirroring the canonicalizer (D179): a non-integral magnitude
    # too small to round-trip as a fixed-point decimal (~<1e-17) has no lossless
    # canonical form — it would canonicalize to a false "0.000…0" and collide with
    # every other such value. Refuse at parse, like the upper bound, so a tiny
    # scalar VALUE is a LOAD error in both impls, never a verify-vs-hash split.
    if f != int(f) and not _fixed_point_round_trips(f):
        raise TypeMismatch(
            f"value {f!r} is too small to canonicalize as a fixed-point decimal "
            "without loss; encode it as a string")


def parse(v: Any) -> Scalar:
    """Parse a plain JSON/YAML value into a typed scalar."""
    if isinstance(v, bool):
        return Scalar("bool", v, v)
    if isinstance(v, (int, float)):
        _safe_num(float(v))
        return Scalar("number", float(v), v)
    if isinstance(v, list):
        return Scalar("list", [parse(x) for x in v], v)
    if isinstance(v, dict):
        # money object form: {amount, currency}
        if set(v.keys()) >= {"amount", "currency"}:
            # amount must BE a number (schema: amount:{type:number}) — a
            # string "100" is refused, matching the Go runtime; float()
            # coercion here let the reference accept what Go rejects
            # (cross-impl parity, review fix)
            amt = v["amount"]
            if isinstance(amt, bool) or not isinstance(amt, (int, float)):
                raise TypeMismatch(f"money amount must be a number: {v!r}")
            _safe_num(float(amt))
            return Scalar("money", (float(amt), str(v["currency"])), v)
        raise TypeMismatch(f"cannot type object value: {v!r}")
    if isinstance(v, str):
        for regex, kind in ((_DURATION_RE, "duration"), (_MONEY_RE, "money"),
                            (_PERCENT_RE, "percent"), (_BYTES_RE, "bytes"),
                            (_PROTO_RE, "protocol")):
            m = regex.match(v.strip())
            if not m:
                continue
            if kind == "duration":
                ms = float(m.group(1)) * _DURATION_MS[m.group(2)]
                _safe_num(ms)
                return Scalar(kind, ms, v)
            if kind == "money":
                _safe_num(float(m.group(1)))
                return Scalar(kind, (float(m.group(1)), m.group(2)), v)
            if kind == "percent":
                _safe_num(float(m.group(1)))
                return Scalar(kind, float(m.group(1)), v)
            if kind == "bytes":
                b = float(m.group(1)) * _BYTES_MUL[m.group(2)]
                _safe_num(b)
                return Scalar(kind, int(b), v)
            if kind == "protocol":
                return Scalar(kind, (m.group(1), int(m.group(2)),
                                     int(m.group(3) or 0), int(m.group(4) or 0)), v)
        return Scalar("string", v, v)
    raise TypeMismatch(f"unsupported value: {v!r}")


def _require_same_kind(a: Scalar, b: Scalar) -> None:
    if a.kind != b.kind:
        raise TypeMismatch(f"cannot compare {a.kind} with {b.kind} ({a!r} vs {b!r})")
    if a.kind == "money" and a.value[1] != b.value[1]:
        raise TypeMismatch(f"currency mismatch: {a.value[1]} vs {b.value[1]}")


ORDERABLE_KINDS = {"duration", "money", "percent", "bytes", "number"}


def _ordinal(s: Scalar) -> Any:
    if s.kind == "money":
        return s.value[0]
    if s.kind in ORDERABLE_KINDS:
        return s.value
    raise TypeMismatch(f"{s.kind} is not orderable")


def _value_equal(a: Scalar, b: Scalar) -> bool:
    """Canonical equality (D25): 5m == 300s inside a list exactly as
    outside one. Comparing whole Scalars would drag the raw spelling in."""
    if a.kind != b.kind:
        return False
    if a.kind == "list":
        return (len(a.value) == len(b.value)
                and all(_value_equal(x, y) for x, y in zip(a.value, b.value)))
    return a.value == b.value


# ---- operators -------------------------------------------------------------

def _list_equal(a: Scalar, b: Scalar):
    """Strong-Kleene list equality (D21): "same length AND every position equal".
    A definite F dominates ⊥ — a length mismatch (a structural inequality, no
    element compared) or any well-typed definite element mismatch proves the lists
    unequal regardless of ill-typed positions elsewhere. Equality is undecidable
    (raises TypeMismatch → unverifiable) only when every position is equal-or-ill-
    typed and at least one is ill-typed. Order-independent: a definite F wins."""
    al, bl = a.value, b.value
    if len(al) != len(bl):
        return False  # length alone proves inequality; no element compared
    unver = None
    for x, y in zip(al, bl):
        try:
            eq = op_equals(x, y)  # three-valued; recurses for nested lists
        except TypeMismatch as e:
            unver = e  # ⊥ here — remember, keep scanning for a definite F
            continue
        if not eq:
            return False  # a well-typed mismatch proves inequality (F dominates ⊥)
    if unver is not None:
        raise unver  # some position ⊥, none definitely unequal → undecidable
    return True


def op_equals(a: Scalar, b: Scalar) -> bool:
    _require_same_kind(a, b)
    if a.kind == "list":
        return _list_equal(a, b)
    return _value_equal(a, b)

def op_lte(a: Scalar, b: Scalar) -> bool:
    _require_same_kind(a, b)
    return _ordinal(a) <= _ordinal(b)

def op_gte(a: Scalar, b: Scalar) -> bool:
    _require_same_kind(a, b)
    return _ordinal(a) >= _ordinal(b)

def op_in(a: Scalar, b: Scalar) -> bool:
    """Strong-Kleene membership: a DISJUNCTION of `a == x`. A definite match (T)
    dominates ⊥, proving membership regardless of ill-typed elements. With no
    definite match: an ill-typed element (⊥) makes the disjunction undecidable —
    it could have been the match, so "not in" would be a fail-open (and `not-in`
    would falsely satisfy). Only when every element is well-typed and none matched
    is `a` definitely not in. A list with NO comparable element (incl. empty) is
    unverifiable (D14) — it falls out of "no match and nothing well-typed"."""
    if b.kind != "list":
        raise TypeMismatch("`in` requires a list on the right side")
    any_comparable = False
    unver = None
    for x in b.value:
        try:
            eq = op_equals(a, x)
        except TypeMismatch as e:
            unver = e  # ⊥ — this element could be the match; remember it
            continue
        any_comparable = True
        if eq:
            return True  # a definite match proves membership (T dominates ⊥)
    if not any_comparable:
        raise TypeMismatch(
            f"no element of the list is comparable with {a!r} (D14)")
    if unver is not None:
        raise unver  # a well-typed non-match, but an ill-typed pair could match → ⊥
    return False  # every element well-typed and none matched → definitely not in

def op_subset_of(a: Scalar, b: Scalar) -> bool:
    """Strong-Kleene universal membership: ∀ x∈A: (x in B), each `in` three-valued
    via op_in. A definite non-member (F) proves A is not a subset; if none is a
    definite non-member but some membership is ⊥, the relation is unverifiable —
    never coerced to a verdict resting on an incomparable comparison."""
    if a.kind != "list" or b.kind != "list":
        raise TypeMismatch("`subset-of` requires lists on both sides")
    unver = None
    for x in a.value:
        try:
            member = op_in(x, b)
        except TypeMismatch as e:
            unver = e  # membership of x is ⊥ — remember, keep scanning for a definite F
            continue
        if not member:
            return False  # x is definitely not in B → A is not a subset (F dominates)
    if unver is not None:
        raise unver  # some membership ⊥, none definitely false → undecidable
    return True

def op_compatible_with(a: Scalar, b: Scalar) -> bool:
    """candidate `a` compatible-with required `b`: same protocol name,
    same major, candidate version >= required version."""
    if a.kind != "protocol" or b.kind != "protocol":
        raise TypeMismatch("`compatible-with` requires protocol values")
    an, amaj, amin, apat = a.value
    bn, bmaj, bmin, bpat = b.value
    return an == bn and amaj == bmaj and (amin, apat) >= (bmin, bpat)


OPERATORS = {
    "equals":          op_equals,
    "not-equals":      lambda a, b: not op_equals(a, b),
    "lte":             op_lte,
    "gte":             op_gte,
    "in":              op_in,
    "not-in":          lambda a, b: not op_in(a, b),
    "subset-of":       op_subset_of,
    "compatible-with": op_compatible_with,
    # exists / absent are handled by the verifier (they act on presence, not value)
}

PRESENCE_OPERATORS = {"exists", "absent"}
