from __future__ import annotations

import math
import re
from typing import Sequence

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class RegulationRAGService:
    def chunk_text(self, text: str, chunk_size: int = 900) -> list[str]:
        text = re.sub(r"\s+", " ", text).strip()
        if not text:
            return []
        chunks = []
        for i in range(0, len(text), chunk_size):
            chunks.append(text[i : i + chunk_size])
        return chunks

    def retrieve(self, query: str, chunks: Sequence[str], top_k: int = 3) -> list[str]:
        if not chunks:
            return []
        vectorizer = TfidfVectorizer(stop_words="english")
        matrix = vectorizer.fit_transform([query, *chunks])
        query_vec = matrix[0:1]
        chunk_vecs = matrix[1:]
        sims = cosine_similarity(query_vec, chunk_vecs)[0]
        ranked = sorted(enumerate(sims), key=lambda x: x[1], reverse=True)[: min(top_k, len(chunks))]
        return [chunks[idx] for idx, score in ranked if not math.isnan(score)]
