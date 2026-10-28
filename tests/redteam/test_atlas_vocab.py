"""Every MITRE ATLAS reference must match the pinned official vocabulary.

An ATLAS ID written from memory can name the wrong technique and still read as
authoritative: the battery once tagged prompt injection as AML.T0040, which is
"AI Model Inference API Access". These tests fail on any tag or "ID (Name)"
mention that the vocabulary in `redteam/atlas.py` does not confirm.
"""

import re
from pathlib import Path

import pytest

from sec_recon_agent.redteam.atlas import ATLAS_TECHNIQUES
from sec_recon_agent.redteam.payloads import PAYLOADS

REPO_ROOT = Path(__file__).resolve().parents[2]
_ID = r"AML\.T\d{4}(?:\.\d{3})?"
_DOCS = sorted([*REPO_ROOT.glob("docs/*.md"), REPO_ROOT / "SCORECARD.md"])


def test_every_payload_tag_is_an_atlas_technique() -> None:
    unknown = {(p.id, t) for p in PAYLOADS for t in p.atlas_techniques if t not in ATLAS_TECHNIQUES}
    assert unknown == set(), f"payload tags missing from the ATLAS vocabulary: {sorted(unknown)}"


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: p.name)
def test_every_atlas_id_in_docs_exists(doc: Path) -> None:
    ids = set(re.findall(_ID, doc.read_text(encoding="utf-8")))
    unknown = sorted(i for i in ids if i not in ATLAS_TECHNIQUES)
    assert unknown == [], f"{doc.name} cites IDs that are not ATLAS techniques: {unknown}"


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: p.name)
def test_every_named_atlas_id_in_docs_uses_the_official_name(doc: Path) -> None:
    pairs = re.findall(rf"({_ID}) \(([^)]+)\)", doc.read_text(encoding="utf-8"))
    wrong = sorted(
        (tid, name, ATLAS_TECHNIQUES[tid])
        for tid, name in pairs
        if tid in ATLAS_TECHNIQUES and name != ATLAS_TECHNIQUES[tid]
    )
    assert wrong == [], f"{doc.name} names ATLAS IDs wrongly (id, written, official): {wrong}"
