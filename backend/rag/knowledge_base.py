"""
RAG knowledge base: TF-IDF over compliance framework documents.

Uses scikit-learn's TfidfVectorizer with English stop-word removal and
unigram + bigram features (cf. dissertation §3.3 and §4.5). retrieve()
returns the top-k most relevant documents for a given query, optionally
restricted to a filter set of document IDs.
"""

import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from backend.paths import DATA_DIR

DATA_PATH = DATA_DIR / "compliance_docs" / "frameworks.json"


class KnowledgeBase:
    def __init__(self):
        with open(DATA_PATH) as f:
            raw = json.load(f)
        self.documents: list[dict] = raw["documents"]
        self._build_index()

    def _build_index(self) -> None:
        corpus = [f"{d['title']}. {d['text']}" for d in self.documents]
        self._vectorizer = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            lowercase=True,
        )
        self._doc_vectors = self._vectorizer.fit_transform(corpus)

    def retrieve(
        self,
        query: str,
        k: int = 3,
        filter_doc_ids: list[str] | None = None,
    ) -> list[dict]:
        q_vec = self._vectorizer.transform([query])
        sims = cosine_similarity(q_vec, self._doc_vectors).ravel()

        candidate_idx = (
            [i for i, d in enumerate(self.documents) if d["id"] in filter_doc_ids]
            if filter_doc_ids
            else list(range(len(self.documents)))
        )
        ranked = sorted(candidate_idx, key=lambda i: sims[i], reverse=True)
        return [self.documents[i] for i in ranked[:k]]

    def get_by_id(self, doc_id: str) -> dict | None:
        return next((d for d in self.documents if d["id"] == doc_id), None)


_kb: KnowledgeBase | None = None


def get_knowledge_base() -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb
