from __future__ import annotations

from app.models.schemas import MitreTechnique
from app.paths import RAG_DIR


class HashEmbeddingFunction:
    def name(self) -> str:
        return "default"

    def __call__(self, input):
        import hashlib
        import math

        vectors = []
        for text in input:
            vector = [0.0] * 64
            for token in str(text).lower().split():
                digest = hashlib.sha256(token.encode("utf-8")).digest()
                vector[digest[0] % 64] += 1.0
            norm = math.sqrt(sum(v * v for v in vector)) or 1.0
            vectors.append([v / norm for v in vector])
        return vectors


def persist_chroma_corpus(techniques: list[MitreTechnique]) -> bool:
    """Persist ATT&CK docs to ChromaDB for offline demo RAG.

    The deterministic TF-IDF retriever remains the API fallback so the demo works
    even if a local Chroma build has platform issues.
    """
    try:
        import chromadb

        client = chromadb.PersistentClient(path=str(RAG_DIR / "chroma"))
        collection = client.get_or_create_collection("mitre_enterprise_attack", embedding_function=HashEmbeddingFunction())
        existing = collection.count()
        if existing >= len(techniques):
            return True
        ids = [t.id for t in techniques]
        docs = [f"{t.id} {t.name}\nTactics: {', '.join(t.tactics)}\n{t.description}\nMitigations: {'; '.join(t.mitigations)}" for t in techniques]
        metas = [{"name": t.name, "url": t.url, "tactics": ",".join(t.tactics)} for t in techniques]
        collection.upsert(ids=ids, documents=docs, metadatas=metas)
        return True
    except Exception:
        return False
