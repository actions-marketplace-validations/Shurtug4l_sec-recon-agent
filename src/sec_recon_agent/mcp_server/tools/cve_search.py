"""Semantic search over recent high-severity CVEs.

Two surfaces:
- `seed_index()`: one-shot script (`uv run sec-recon-seed`) that pulls recent
  CRITICAL+HIGH CVEs from NVD and indexes their descriptions in ChromaDB.
- `cve_semantic_search(query, top_k)`: MCP tool that returns the closest
  matches as a list of CVECandidate.

Embedding: ChromaDB's DefaultEmbeddingFunction (ONNX MiniLM-L6, 384-d).
Self-contained, no torch / transformers dependency, ~10x faster cold start.
Distance: cosine (HNSW), exposed as similarity = 1 - distance, clamped to [0, 1].

Retrieval is hybrid by default (RETRIEVAL_HYBRID_ENABLED): the dense cosine
ranking is fused via reciprocal-rank fusion with an in-process BM25 over the
same corpus (see hybrid.py for the why). The CVECandidate contract is
unchanged: `similarity` is always the cosine similarity of that document to
the query; only the rank ORDER comes from the fusion. The BM25 index is
built lazily at first query from the ChromaDB collection and cached per
process; seeding runs in a separate process, so a long-lived server picks up
a re-seeded corpus on restart (in-process seeding, as in tests, invalidates
the cache directly).
"""

import asyncio
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from sec_recon_agent.config import settings
from sec_recon_agent.mcp_server.effects import declared_tool
from sec_recon_agent.mcp_server.hybrid import Bm25Index, cosine_similarity, rrf_fuse
from sec_recon_agent.mcp_server.models import CVE_CANDIDATE_SUMMARY_CHARS, CVECandidate
from sec_recon_agent.mcp_server.nvd_client import HTTP_TIMEOUT_SECONDS, nvd_get
from sec_recon_agent.mcp_server.security import fence_untrusted
from sec_recon_agent.observability import get_tracer

log = structlog.get_logger()
_tracer = get_tracer()

COLLECTION_NAME = "cve_descriptions"
# 30-day default: yields ~5-8k recent high-severity CVEs which is enough
# for a meaningful semantic-search corpus without saturating the NVD
# public rate budget (~3-4 pages per severity = 6-8 requests total).
# Larger windows are fine with NVD_API_KEY set (50 req/30s vs 5 req/30s).
NVD_LOOKBACK_DAYS = 30
NVD_PAGE_SIZE = 2000
NVD_MAX_PAGES_PER_SEVERITY = 25
UPSERT_BATCH = 500
MAX_TOP_K = 25
MAX_QUERY_CHARS = 2000  # MiniLM-L6 truncates at ~512 tokens; cap early to bound embedding latency
# Candidate depth per retriever before fusion. Deep enough that a document
# missed by one retriever but ranked well by the other survives into the
# fused top_k (top_k <= MAX_TOP_K = 25 << 50).
CANDIDATE_POOL = 50

_collection: Any = None
_embedding_fn: Any = None
_collection_lock = threading.Lock()
_bm25: Bm25Index | None = None
_bm25_lock = threading.Lock()


def _get_collection() -> Any:
    # Double-checked locking. The fast path skips the lock once the collection
    # is built. Without the lock, two concurrent first-callers can both open
    # a PersistentClient on the same SQLite path, which corrupts the index
    # or fails with a lock error from chroma.
    global _collection, _embedding_fn
    if _collection is not None:
        return _collection

    with _collection_lock:
        if _collection is not None:
            return _collection

        import chromadb
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

        settings.chroma_persist_dir.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(settings.chroma_persist_dir))
        # The embedding function is kept alongside the collection: the hybrid
        # path embeds the query once itself so the same vector can score
        # BM25-only candidates (their cosine is not in the dense result).
        _embedding_fn = DefaultEmbeddingFunction()
        _collection = client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=_embedding_fn,
            metadata={"hnsw:space": "cosine"},
        )
        return _collection


def _get_bm25() -> Bm25Index:
    # Same double-checked locking as _get_collection. The build tokenizes the
    # whole corpus (one-time, seconds at most on the seeded index) and must
    # not run twice concurrently.
    global _bm25
    if _bm25 is not None:
        return _bm25

    with _bm25_lock:
        if _bm25 is not None:
            return _bm25

        collection = _get_collection()
        got = collection.get(include=["documents"])
        ids = [str(doc_id) for doc_id in (got.get("ids") or [])]
        docs = [str(doc) if doc else "" for doc in (got.get("documents") or [])]
        _bm25 = Bm25Index(ids, docs)
        log.info("bm25_index_built", docs=len(ids))
        return _bm25


def _reset_collection_cache() -> None:
    """Reset the module-level collection + BM25 caches. Intended for tests only."""
    global _collection, _embedding_fn, _bm25
    _collection = None
    _embedding_fn = None
    _bm25 = None


def _vuln_to_record(vuln: dict[str, Any]) -> tuple[str, str, dict[str, Any]] | None:
    cve = vuln.get("cve")
    if not isinstance(cve, dict):
        return None
    cve_id = cve.get("id")
    if not isinstance(cve_id, str):
        return None

    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = str(desc.get("value", ""))
            break
    if not description:
        return None

    metadata: dict[str, Any] = {"published": str(cve.get("published", ""))}
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            if score is not None:
                metadata["cvss_v3_score"] = float(score)
            if severity is not None:
                metadata["severity"] = str(severity)
            break

    return cve_id, description, metadata


async def _fetch_severity_window(
    client: httpx.AsyncClient,
    severity: str,
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    collected: list[dict[str, Any]] = []
    index = 0
    # Hard page cap so a malformed totalResults from NVD cannot push us into
    # an effectively unbounded fetch loop that exhausts the rate budget.
    for _ in range(NVD_MAX_PAGES_PER_SEVERITY):
        payload = await nvd_get(
            client,
            params={
                "cvssV3Severity": severity,
                "lastModStartDate": start.strftime(fmt),
                "lastModEndDate": end.strftime(fmt),
                "resultsPerPage": NVD_PAGE_SIZE,
                "startIndex": index,
            },
        )
        batch = payload.get("vulnerabilities") or []
        collected.extend(batch)
        total = int(payload.get("totalResults", 0))
        index += len(batch)
        log.info(
            "seed_fetch_progress",
            severity=severity,
            fetched=index,
            total=total,
        )
        if not batch or index >= total:
            break
    else:
        log.warning("seed_page_cap_reached", severity=severity, cap=NVD_MAX_PAGES_PER_SEVERITY)
    return collected


async def _seed_index_async(lookback_days: int = NVD_LOOKBACK_DAYS) -> int:
    collection = _get_collection()

    end = datetime.now(UTC)
    start = end - timedelta(days=lookback_days)
    log.info("seed_starting", lookback_days=lookback_days)

    vulns: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        for severity in ("CRITICAL", "HIGH"):
            vulns.extend(await _fetch_severity_window(client, severity, start, end))

    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []
    seen: set[str] = set()
    for vuln in vulns:
        record = _vuln_to_record(vuln)
        if record is None:
            continue
        cve_id, description, metadata = record
        if cve_id in seen:
            continue
        seen.add(cve_id)
        ids.append(cve_id)
        documents.append(description)
        metadatas.append(metadata)

    if not ids:
        log.warning("seed_no_records")
        return 0

    log.info("seed_upserting", count=len(ids))
    for i in range(0, len(ids), UPSERT_BATCH):
        collection.upsert(
            ids=ids[i : i + UPSERT_BATCH],
            documents=documents[i : i + UPSERT_BATCH],
            metadatas=metadatas[i : i + UPSERT_BATCH],
        )
    # In-process seeding (tests, embedded use) must invalidate the BM25 cache
    # or the lexical arm would keep ranking the pre-seed corpus. The normal
    # deployment seeds in a separate process, where this is a no-op.
    global _bm25
    _bm25 = None
    log.info("seed_done", indexed=len(ids))
    return len(ids)


def seed_index() -> None:
    """Entry point for `uv run sec-recon-seed`."""
    indexed = asyncio.run(_seed_index_async())
    log.info("seed_script_exit", indexed=indexed)


@declared_tool()
async def cve_semantic_search(query: str, top_k: int = 5) -> list[CVECandidate]:
    """Find recent high-severity CVEs whose descriptions match the query semantically.

    Returns up to top_k CVECandidate results ranked by cosine similarity over
    embeddings of the CVE description text.
    """
    with _tracer.start_as_current_span("tool.cve_semantic_search") as span:
        # query.length is a useful operational signal; query text itself
        # is NOT recorded (it may contain user PII or instruction-like
        # content from a hostile prompt).
        hybrid = settings.retrieval_hybrid_enabled
        span.set_attribute("tool.name", "cve_semantic_search")
        span.set_attribute("query.length", len(query))
        span.set_attribute("query.top_k", top_k)
        span.set_attribute("retrieval.hybrid", hybrid)
        if not query.strip():
            span.set_attribute("tool.success", True)
            span.set_attribute("results.count", 0)
            return []
        # Cap defensively at the tool boundary: the FastAPI layer caps user
        # input at 100,000 chars, and the agent can synthesize long queries.
        query = query[:MAX_QUERY_CHARS]
        top_k = max(1, min(top_k, MAX_TOP_K))

        try:
            if hybrid:
                triples = await asyncio.to_thread(_hybrid_query_sync, query, top_k)
            else:
                triples = await asyncio.to_thread(_dense_query_sync, query, top_k)
        except Exception as exc:
            span.set_attribute("tool.success", False)
            span.record_exception(exc)
            raise

        candidates: list[CVECandidate] = []
        for cve_id, doc, similarity in triples:
            raw_summary = doc[:CVE_CANDIDATE_SUMMARY_CHARS]
            candidates.append(
                CVECandidate(
                    cve_id=cve_id,
                    summary=fence_untrusted(raw_summary, max_chars=CVE_CANDIDATE_SUMMARY_CHARS)
                    or "",
                    similarity=similarity,
                ),
            )
        span.set_attribute("tool.success", True)
        span.set_attribute("results.count", len(candidates))
        log.info(
            "cve_semantic_search_done",
            query_len=len(query),
            hits=len(candidates),
            hybrid=hybrid,
        )
        return candidates


def _parse_dense_result(result: dict[str, Any]) -> list[tuple[str, str, float]]:
    """Flatten a chroma query result into (cve_id, document, similarity) triples.

    Similarity is 1 - cosine distance, clamped to [0, 1] (HNSW cosine distance
    can exceed 1.0 by float error on anti-correlated vectors).
    """
    ids_batches = result.get("ids") or [[]]
    doc_batches = result.get("documents") or [[]]
    dist_batches = result.get("distances") or [[]]
    ids = ids_batches[0] if ids_batches else []
    docs = doc_batches[0] if doc_batches else []
    distances = dist_batches[0] if dist_batches else []

    return [
        (str(cve_id), str(doc) if doc else "", max(0.0, min(1.0, 1.0 - float(dist))))
        for cve_id, doc, dist in zip(ids, docs, distances, strict=False)
    ]


def _dense_query_sync(query: str, top_k: int) -> list[tuple[str, str, float]]:
    """Dense-only retrieval: the pre-hybrid behavior, byte for byte."""
    collection = _get_collection()
    result: dict[str, Any] = collection.query(query_texts=[query], n_results=top_k)
    return _parse_dense_result(result)


def _hybrid_query_sync(query: str, top_k: int) -> list[tuple[str, str, float]]:
    """Dense + BM25 retrieval fused with RRF.

    Both retrievers rank CANDIDATE_POOL candidates; RRF fuses the two
    rankings and the fused top_k is returned. Every candidate keeps its true
    cosine similarity to the query: for dense hits it comes from the HNSW
    distance, for BM25-only hits it is computed against the stored embedding
    with the same query vector (so the CVECandidate contract is unchanged).
    """
    collection = _get_collection()
    bm25 = _get_bm25()
    if len(bm25) == 0:
        return []
    pool = min(max(CANDIDATE_POOL, top_k), len(bm25))

    # Embed once; reused for the dense query and for BM25-only candidates.
    query_vector = _embedding_fn([query])[0]
    dense_result: dict[str, Any] = collection.query(
        query_embeddings=[query_vector],
        n_results=pool,
    )
    dense = _parse_dense_result(dense_result)
    lexical_ids = bm25.search(query, top_n=pool)
    fused_ids = rrf_fuse([[cve_id for cve_id, _, _ in dense], lexical_ids])[:top_k]

    by_id: dict[str, tuple[str, float]] = {cve_id: (doc, sim) for cve_id, doc, sim in dense}
    missing = [cve_id for cve_id in fused_ids if cve_id not in by_id]
    if missing:
        got = collection.get(ids=missing, include=["documents", "embeddings"])
        for cve_id, doc, embedding in zip(
            got.get("ids") or [],
            got.get("documents") or [],
            got.get("embeddings") if got.get("embeddings") is not None else [],
            strict=False,
        ):
            similarity = max(0.0, min(1.0, cosine_similarity(query_vector, embedding)))
            by_id[str(cve_id)] = (str(doc) if doc else "", similarity)

    return [(cve_id, by_id[cve_id][0], by_id[cve_id][1]) for cve_id in fused_ids if cve_id in by_id]
