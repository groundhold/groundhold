"""Attribute vocabularies — the per-capability type system (D10).

A vocabulary is an OPTIONAL, strengthening input (D23): without one,
loading and verification behave exactly as before. With one, candidate
values on vocabulary paths are kind/enum-checked at load (fail-fast, D19)
and every verdict carries a pathInVocabulary flag. Paths outside the
vocabulary stay legal — extension governance is an open question.
"""
from __future__ import annotations
from dataclasses import dataclass
import glob
import os


from .yamlcompat import safe_load as _core12_load

from .contract import ContractError, read_document


@dataclass
class Vocabulary:
    capability: str
    version: str
    attributes: dict[str, dict]   # path -> {kind, enum?, ...}
    stateful: bool = False        # D47


# The CLOSED key sets a vocabulary document may use (D701), mirroring the runtime.
# A key nothing reads is silently dropped, and `note:` rode on twelve shipped
# attributes with no consumer at all — indistinguishable, to its author, from working.
# Every key below has one.
_DOC_KEYS = {"capability", "version", "stateful", "protection", "attributes"}
_ATTR_KEYS = {"kind", "description", "mappings", "evidence", "verification",
              "enum", "recommended", "note", "unordered"}


def _check_vocab_keys(path: str, doc: dict) -> None:
    for k in sorted(doc):
        if k not in _DOC_KEYS:
            raise ContractError(
                f"{path}: unknown vocabulary key {k!r} — a key nothing reads is "
                f"silently dropped, so it is refused instead")
    for attr in sorted(doc.get("attributes") or {}):
        spec = (doc.get("attributes") or {})[attr]
        if not isinstance(spec, dict):
            raise ContractError(f"{path}: attribute {attr!r} is not a mapping")
        for k in sorted(spec):
            if k not in _ATTR_KEYS:
                raise ContractError(
                    f"{path}: attribute {attr!r} has unknown key {k!r} — a key "
                    f"nothing reads is silently dropped, so it is refused instead")


def load_vocab_dir(dirpath: str) -> dict[str, Vocabulary]:
    """Load every vocabulary document in a directory, indexed by
    capability type."""
    vocabs: dict[str, Vocabulary] = {}
    for path in sorted(glob.glob(os.path.join(dirpath, "*.yaml"))):
        doc = _core12_load(read_document(path))
        if not isinstance(doc, dict) or not doc.get("capability"):
            raise ContractError(f"{path}: not a vocabulary document")
        _check_vocab_keys(path, doc)
        vocabs[doc["capability"]] = Vocabulary(
            capability=doc["capability"],
            version=str(doc.get("version", "")),
            attributes=doc.get("attributes") or {},
            stateful=bool(doc.get("stateful")),
        )
    return vocabs
