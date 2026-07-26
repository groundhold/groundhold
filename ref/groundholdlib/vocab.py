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

import yaml

from .yamlcompat import safe_load as _core12_load

from .contract import ContractError, read_document


@dataclass
class Vocabulary:
    capability: str
    version: str
    attributes: dict[str, dict]   # path -> {kind, enum?, ...}
    stateful: bool = False        # D47


def load_vocab_dir(dirpath: str) -> dict[str, Vocabulary]:
    """Load every vocabulary document in a directory, indexed by
    capability type."""
    vocabs: dict[str, Vocabulary] = {}
    for path in sorted(glob.glob(os.path.join(dirpath, "*.yaml"))):
        doc = _core12_load(read_document(path))
        if not isinstance(doc, dict) or not doc.get("capability"):
            raise ContractError(f"{path}: not a vocabulary document")
        vocabs[doc["capability"]] = Vocabulary(
            capability=doc["capability"],
            version=str(doc.get("version", "")),
            attributes=doc.get("attributes") or {},
            stateful=bool(doc.get("stateful")),
        )
    return vocabs
