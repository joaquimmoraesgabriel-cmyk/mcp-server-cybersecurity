"""Optional real E5 embeddings. Query paths never download weights."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

from .models import KnowledgeError

MODEL_ID = "intfloat/multilingual-e5-small"


def prepare_model(data_dir: Path, revision: str | None = None) -> dict:
    from huggingface_hub import HfApi, snapshot_download

    from .snapshot import atomic_json

    sha = HfApi().model_info(MODEL_ID, revision=revision, token=False).sha
    if not sha or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise KnowledgeError("INDEX_UNAVAILABLE", "Não foi possível fixar a revisão do modelo.")
    directory = data_dir / "models" / sha
    snapshot_download(
        MODEL_ID,
        revision=sha,
        local_dir=directory,
        allow_patterns=["*.json", "*.safetensors", "*.txt", "*.model", "README.md", "LICENSE*"],
        ignore_patterns=["onnx/*", "openvino/*", "*.bin"],
        token=False,
    )
    manifest = {"model_id": MODEL_ID, "revision": sha, "dimensions": 384}
    atomic_json(data_dir / "model.json", manifest)
    return manifest


class LocalEmbedding:
    def __init__(self, data_dir: Path, manifest: dict | None = None):
        try:
            import torch
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise KnowledgeError(
                "INDEX_UNAVAILABLE", "Instale o extra semantic e prepare o modelo."
            ) from None
        # Keep local inference from occupying every CPU thread on the user's computer.
        torch.set_num_threads(min(4, os.cpu_count() or 1))
        try:
            self.manifest = manifest or json.loads((data_dir / "model.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise KnowledgeError(
                "INDEX_UNAVAILABLE", "Execute models prepare antes da indexação semântica."
            ) from None
        sha = self.manifest.get("revision", "")
        if (
            self.manifest.get("model_id") != MODEL_ID
            or not re.fullmatch(r"[0-9a-f]{40}", sha)
            or self.manifest.get("dimensions") != 384
        ):
            raise KnowledgeError("INDEX_UNAVAILABLE", "Manifesto de modelo inválido.")
        self.model = SentenceTransformer(
            str(data_dir / "models" / sha), device="cpu", local_files_only=True, trust_remote_code=False
        )
        self.model.max_seq_length = 512

    def passages(self, text: str, context: str) -> list[str]:
        tokenizer = self.model.tokenizer
        context_ids = tokenizer.encode(context, add_special_tokens=False, verbose=False)[:70]
        context = tokenizer.decode(context_ids)
        token_ids = tokenizer.encode(text, add_special_tokens=False, verbose=False)
        parts = []
        for offset in range(0, len(token_ids), 320):
            ids = token_ids[offset : offset + 350]
            # Decoding/encoding can change token counts. Shrink until the real input fits.
            while ids:
                passage = context + "\n" + tokenizer.decode(ids)
                if len(tokenizer.encode("passage: " + passage, verbose=False)) <= 512:
                    break
                ids = ids[:-10]
            if ids:
                parts.append(passage)
        return parts

    def encode(self, texts: list[str], query: bool = False):
        prefix = "query: " if query else "passage: "
        inputs = [prefix + value for value in texts]
        if any(len(self.model.tokenizer.encode(value, verbose=False)) > 512 for value in inputs):
            raise KnowledgeError(
                "INVALID_ARGUMENT", "Consulta excede 512 tokens do embedding; reduza o texto."
            )
        return self.model.encode(
            inputs, batch_size=16, normalize_embeddings=True, show_progress_bar=False
        ).tolist()


def build_vectors(path: Path, passages: list[tuple[str, str, str]], embedding: LocalEmbedding) -> None:
    from qdrant_client import QdrantClient, models

    client = QdrantClient(path=str(path))
    try:
        client.create_collection(
            "chunks", vectors_config=models.VectorParams(size=384, distance=models.Distance.COSINE)
        )
        for start in range(0, len(passages), 32):
            batch = passages[start : start + 32]
            vectors = embedding.encode([item[2] for item in batch])
            points = [
                models.PointStruct(
                    id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{cid}:{start + i}")),
                    vector=vector,
                    payload={"chunk_id": cid, "document_id": did},
                )
                for i, ((cid, did, _), vector) in enumerate(zip(batch, vectors))
            ]
            client.upsert("chunks", points=points)
    finally:
        client.close()
