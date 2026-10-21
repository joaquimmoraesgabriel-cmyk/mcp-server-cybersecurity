"""Opt-in integration tests using real, already-downloaded E5 weights.

Set CYBER_RAG_TEST_MODEL_DIR to a prepared Cyber RAG data directory (model.json
and models/<revision>) or the actual weights directory named by its 40-char SHA.
No fake vectors, mocked encoders, model download or LLM calls are used here.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from cyber_rag.embeddings import MODEL_ID, LocalEmbedding
from cyber_rag.ingestion import load_manifest
from cyber_rag.models import KnowledgeError
from cyber_rag.service import KnowledgeService
from cyber_rag.snapshot import atomic_json, ingest_documents

FIXTURES = Path(__file__).parent / "fixtures"


def _copy_or_link(source: str, destination: str) -> str:
    """Reuse immutable weights on one volume; copy when hardlinks are unavailable."""
    try:
        os.link(source, destination)
        return destination
    except OSError:
        return shutil.copy2(source, destination)


@pytest.fixture(scope="module")
def real_model_bundle(tmp_path_factory: pytest.TempPathFactory):
    configured = os.environ.get("CYBER_RAG_TEST_MODEL_DIR")
    if not configured:
        pytest.skip("Real semantic integration not run: set CYBER_RAG_TEST_MODEL_DIR to local E5 weights.")
    supplied = Path(configured).expanduser().resolve()
    if not supplied.is_dir():
        pytest.skip("Real semantic integration not run: configured local model directory is absent.")
    if (supplied / "model.json").is_file():
        manifest = json.loads((supplied / "model.json").read_text(encoding="utf-8"))
        weights = supplied / "models" / manifest.get("revision", "")
    elif re.fullmatch(r"[0-9a-f]{40}", supplied.name):
        manifest = {"model_id": MODEL_ID, "revision": supplied.name, "dimensions": 384}
        weights = supplied
    else:
        pytest.skip("Real semantic integration not run: expected model.json or a SHA-named weights folder.")
    assert manifest.get("model_id") == MODEL_ID, "Configure the supported real multilingual-e5-small model."
    assert re.fullmatch(r"[0-9a-f]{40}", manifest.get("revision", "")), "Model revision must be pinned."
    if not (weights / "config.json").is_file() or not list(weights.rglob("*.safetensors")):
        pytest.skip("Real semantic integration not run: model configuration or safetensors weights are absent.")

    environment = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1"}
    previous = {key: os.environ.get(key) for key in environment}
    os.environ.update(environment)
    network = {"active": True, "attempts": []}

    def forbid_network(event, arguments):
        if network["active"] and event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo"}:
            network["attempts"].append(event)
            raise AssertionError("Offline semantic test attempted network access.")

    # Audit hooks observe and block actual socket operations; embeddings remain real.
    sys.addaudithook(forbid_network)
    try:
        pytest.importorskip("sentence_transformers", reason="Install the semantic extra to run real embeddings.")
        pytest.importorskip("qdrant_client", reason="Qdrant is required for real vector integration.")
        directory = tmp_path_factory.mktemp("real-semantic-integration")
        destination = directory / "models" / manifest["revision"]
        shutil.copytree(weights, destination, copy_function=_copy_or_link)
        atomic_json(directory / "model.json", manifest)
        yield directory, manifest, network
        assert not network["attempts"], "A network attempt was suppressed by a dependency."
    finally:
        network["active"] = False
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_real_e5_vectors_and_token_limits(real_model_bundle) -> None:
    directory, manifest, _ = real_model_bundle
    embedding = LocalEmbedding(directory)
    assert embedding.manifest == manifest
    vectors = embedding.encode(["Use parameterized queries.", "Use consultas parametrizadas."], query=True)
    assert len(vectors) == 2
    for vector in vectors:
        assert len(vector) == 384
        assert all(math.isfinite(value) for value in vector)
        assert math.isclose(sum(value * value for value in vector), 1.0, rel_tol=1e-4, abs_tol=1e-4)

    source = "Consultas parametrizadas separam valores e estrutura. Parameterized SQL queries. " * 120
    passages = embedding.passages(source, "SYNTHETIC TOKEN LIMIT FIXTURE " * 90)
    assert len(passages) > 1
    tokenizer = embedding.model.tokenizer
    assert all(len(tokenizer.encode("passage: " + passage)) <= 512 for passage in passages)
    too_long = "database " * 1200
    assert len(tokenizer.encode("query: " + too_long)) > 512
    with pytest.raises(KnowledgeError) as error:
        embedding.encode([too_long], query=True)
    assert error.value.code == "INVALID_ARGUMENT"


def test_real_vector_rebuild_and_offline_snapshot_switch(real_model_bundle) -> None:
    directory, model_manifest, network = real_model_bundle
    documents, sources = load_manifest(FIXTURES / "sources.json")
    documents = [document for document in documents if document.source_id in {"owasp", "sigma"}]
    sources = {key: source for key, source in sources.items() if key in {"owasp", "sigma"}}
    lexical = ingest_documents(directory, documents, sources, embedding_mode="lexical")
    query = "database safety with bind variables"
    service = KnowledgeService(directory)
    try:
        lexical_result = service.dispatch("knowledge_search", {"query": query, "limit": 10})
        assert lexical_result["snapshot_id"] == lexical["snapshot_id"]
        # These words do not occur in either selected fixture. Lexical-only retrieval is insufficient.
        assert lexical_result["status"] == "no_results", lexical_result

        first = ingest_documents(directory, documents, sources, embedding_mode="semantic")
        assert first["model"] == model_manifest
        first_result = service.dispatch("knowledge_search", {"query": query, "limit": 10})
        assert first_result["status"] == "ok", first_result
        assert first_result["snapshot_id"] == first["snapshot_id"]
        assert first_result["retrieval"]["method"] == "exact+bm25+e5+rrf"
        assert any(result["source_id"] == "owasp" for result in first_result["results"])
        assert first_result["citations"]
        assert service._vectors.get_collection("chunks").config.params.vectors.size == 384

        marker = "SYNTHETIC_SECOND_SNAPSHOT_MARKER"
        revised = [replace(document, revision="synthetic-test-fixture-v2",
                           text=document.text + "\n" + marker,
                           raw=document.raw + ("\n" + marker).encode("utf-8")) for document in documents]
        revised_sources = {key: {**source, "revision": "synthetic-test-fixture-v2"}
                           for key, source in sources.items()}
        second = ingest_documents(directory, revised, revised_sources, embedding_mode="semantic")
        assert second["snapshot_id"] != first["snapshot_id"]
        current = service.dispatch("knowledge_search", {"query": query, "limit": 10})
        assert current["status"] == "ok", current
        assert current["snapshot_id"] == second["snapshot_id"]
        assert service._vector_sid == second["snapshot_id"]
        assert all(citation["revision"] == "synthetic-test-fixture-v2" for citation in current["citations"])

        old = service.dispatch("knowledge_search", {
            "query": query, "limit": 10, "snapshot_id": first["snapshot_id"]
        })
        assert old["status"] == "ok", old
        assert old["snapshot_id"] == first["snapshot_id"]
        assert service._vector_sid == first["snapshot_id"]
        assert all(citation["revision"] == "synthetic-test-fixture-v1" for citation in old["citations"])

        # An unsupported model manifest cannot replace the usable vector generation.
        atomic_json(directory / "model.json", {**model_manifest, "model_id": "unsupported/test-only-model"})
        try:
            with pytest.raises(KnowledgeError):
                ingest_documents(directory, revised, revised_sources, embedding_mode="semantic")
            active = json.loads((directory / "active.json").read_text(encoding="utf-8"))
            assert active["snapshot_id"] == second["snapshot_id"]
            pinned = service.dispatch("knowledge_search", {"query": query, "limit": 10})
            assert pinned["status"] == "ok", pinned
            assert pinned["snapshot_id"] == second["snapshot_id"]
        finally:
            atomic_json(directory / "model.json", model_manifest)
        assert not network["attempts"]
    finally:
        service.close()
