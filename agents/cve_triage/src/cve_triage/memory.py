"""Embeddings for the pgvector context memory.

Local model (fastembed, ONNX, default BAAI/bge-small-en-v1.5, 384 dimensions): no CVE text
or inventory data leaves the VPS for embedding. The model is baked into the image at build
time (FASTEMBED_CACHE_PATH), so the read-only container needs no network for it.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from cve_triage.assess import Candidate

Embedder = Callable[[list[str]], list[list[float]]]
DEFAULT_MODEL = "BAAI/bge-small-en-v1.5"
DIMENSIONS = 384
# Memory: ONNX attention grows with batch x tokens^2. 32 texts x ~512 tokens pinned the
# 768m container on the 7-day replay (2026-11-23). ~900 chars is ~200-250 tokens, which keeps
# product, host context, CWE and the first sentences of the description; batch 4 keeps the peak small.
MAX_CHARS = 900
BATCH_SIZE = 4


def case_text(c: Candidate) -> str:
    """What a case 'is about': product, host context, weakness, description. Used for recall and storage."""
    h = c.host
    return (f"{', '.join(c.products)} on {h.get('role')} (zone {h.get('zone')}, "
            f"criticality {h.get('criticality')}, data {h.get('data_class')}). "
            f"CWE: {', '.join(c.cve.get('cwe') or []) or 'n/a'}. {c.cve.get('description') or ''}")[:MAX_CHARS]


class FastEmbedder:
    def __init__(self, model_name: str | None = None):
        from fastembed import TextEmbedding

        self.model_name = model_name or os.getenv("EMBEDDING_MODEL") or DEFAULT_MODEL
        # threads=1: the container has 0.5 CPU; more ONNX threads only add contention
        self._model = TextEmbedding(model_name=self.model_name, threads=1,
                                    cache_dir=os.getenv("FASTEMBED_CACHE_PATH") or None)

    def __call__(self, texts: list[str]) -> list[list[float]]:
        vectors = [v.tolist() for v in self._model.embed(texts, batch_size=BATCH_SIZE)]
        if vectors and len(vectors[0]) != DIMENSIONS:
            raise ValueError(f"{self.model_name} returns {len(vectors[0])} dims; cve.analyses expects {DIMENSIONS}")
        return vectors


def warm_up() -> None:
    """Download the model into FASTEMBED_CACHE_PATH (Docker build step)."""
    FastEmbedder()(["warm up"])


if __name__ == "__main__":
    warm_up()
