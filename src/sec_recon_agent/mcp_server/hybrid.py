"""Hand-rolled Okapi BM25 and reciprocal-rank fusion for hybrid retrieval.

CVE descriptions are lexical-signal-dominant: product names, component
identifiers, version strings. Dense MiniLM embeddings blur exactly those
tokens; BM25 matches them for free. cve_search.py runs both retrievers and
fuses the rankings.

Why hand-rolled: Okapi BM25 is ~50 lines of pure Python over documents
already held in memory; a dependency (rank-bm25) would add supply-chain
surface for no capability. Why RRF over weighted-score fusion: BM25 scores
and cosine similarities live on incommensurable scales, so score mixing
needs a tuned weight that drifts with the corpus; rank fusion needs neither
(Cormack et al., SIGIR 2009).

Everything here is pure and deterministic: no I/O, no globals. The caller
(cve_search) owns index construction and process-level caching.
"""

import math
import re
from collections.abc import Sequence

# Okapi BM25 defaults: the standard operating point from the literature.
# k1 bounds term-frequency saturation, b sets document-length normalization.
BM25_K1 = 1.5
BM25_B = 0.75
# RRF smoothing constant from Cormack et al.; larger k flattens the
# contribution difference between nearby ranks.
RRF_K = 60

# Identifier-like tokens survive whole: log4j, 2.14.1, cve-2021-44228.
# Splitting them (pure alnum runs) would dilute exactly the lexical signal
# BM25 is here to catch.
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")


def tokenize(text: str) -> list[str]:
    """Lowercased tokens, identifier-like tokens kept whole."""
    return _TOKEN_RE.findall(text.lower())


class Bm25Index:
    """In-memory Okapi BM25 over (id, document) pairs.

    Inverted index: term -> [(doc position, term frequency)]. Memory scales
    with total unique-term occurrences; the seeded CVE corpus (thousands of
    one-paragraph descriptions) fits comfortably.
    """

    def __init__(
        self,
        ids: Sequence[str],
        documents: Sequence[str],
        k1: float = BM25_K1,
        b: float = BM25_B,
    ) -> None:
        self.ids = [str(doc_id) for doc_id in ids]
        self._k1 = k1
        self._b = b
        self._postings: dict[str, list[tuple[int, int]]] = {}
        self._doc_lengths: list[int] = []
        for position, document in enumerate(documents):
            tokens = tokenize(document)
            self._doc_lengths.append(len(tokens))
            counts: dict[str, int] = {}
            for token in tokens:
                counts[token] = counts.get(token, 0) + 1
            for token, tf in counts.items():
                self._postings.setdefault(token, []).append((position, tf))
        self._avgdl = sum(self._doc_lengths) / len(self._doc_lengths) if self._doc_lengths else 0.0

    def __len__(self) -> int:
        return len(self.ids)

    def search(self, query: str, top_n: int) -> list[str]:
        """Ids of the top_n BM25-scoring documents, best first.

        Only documents sharing at least one query term score; ties break on
        lexicographic id so rankings are reproducible across processes.
        """
        if top_n <= 0 or not self.ids:
            return []
        n = len(self.ids)
        scores: dict[int, float] = {}
        for token in set(tokenize(query)):
            postings = self._postings.get(token)
            if not postings:
                continue
            df = len(postings)
            idf = math.log(1.0 + (n - df + 0.5) / (df + 0.5))
            for position, tf in postings:
                length_norm = self._k1 * (
                    1.0 - self._b + self._b * self._doc_lengths[position] / self._avgdl
                )
                scores[position] = scores.get(position, 0.0) + idf * (
                    tf * (self._k1 + 1.0) / (tf + length_norm)
                )
        ranked = sorted(scores.items(), key=lambda item: (-item[1], self.ids[item[0]]))
        return [self.ids[position] for position, _ in ranked[:top_n]]


def rrf_fuse(rankings: Sequence[Sequence[str]], k: int = RRF_K) -> list[str]:
    """Reciprocal-rank fusion: score(d) = sum over rankings of 1 / (k + rank).

    Rank is 1-indexed. Documents appearing in several rankings accumulate;
    ties break on best single rank, then lexicographic id, so the fused
    order is deterministic. Contributions are summed with `math.fsum`, which
    is exactly rounded and therefore independent of the order the rankings
    arrive in: with plain `+=`, two documents holding the same multiset of
    ranks could land on different floats (a + a + b != b + a + a in binary
    floating point) and the fused order would depend on which ranking came
    first. Hypothesis found that case.
    """
    contributions: dict[str, list[float]] = {}
    best_rank: dict[str, int] = {}
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            contributions.setdefault(doc_id, []).append(1.0 / (k + rank))
            if rank < best_rank.get(doc_id, rank + 1):
                best_rank[doc_id] = rank
    scores = {doc_id: math.fsum(parts) for doc_id, parts in contributions.items()}
    ordered = sorted(
        scores.items(),
        key=lambda item: (-item[1], best_rank[item[0]], item[0]),
    )
    return [doc_id for doc_id, _ in ordered]


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity between two vectors; 0.0 when either has zero norm."""
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return float(dot / (norm_a * norm_b))
