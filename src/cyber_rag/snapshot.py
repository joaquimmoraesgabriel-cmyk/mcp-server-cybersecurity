"""Immutable SQLite snapshots; a failed build never replaces the active generation."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from pathlib import Path

from filelock import FileLock

from .models import Document, KnowledgeError, digest, utc_now

SCHEMA = """
CREATE TABLE documents (
 document_id TEXT PRIMARY KEY, source_id TEXT, path TEXT, revision TEXT, url TEXT,
 title TEXT, content_type TEXT, original_hash TEXT, metadata TEXT);
CREATE TABLE chunks (
 chunk_id TEXT PRIMARY KEY, document_id TEXT, section_id TEXT, text TEXT);
CREATE VIRTUAL TABLE chunk_fts USING fts5(chunk_id UNINDEXED, title, text, tokenize='unicode61');
CREATE TABLE entities (entity_id TEXT, document_id TEXT, payload TEXT,
 PRIMARY KEY(entity_id,document_id));
CREATE INDEX entities_by_id ON entities(entity_id);
CREATE TABLE relations (relation_id TEXT PRIMARY KEY, subject_id TEXT, predicate TEXT,
 object_id TEXT, evidence_document_id TEXT, evidence_locator TEXT);
CREATE INDEX relations_subject ON relations(subject_id);
CREATE INDEX relations_object ON relations(object_id);
CREATE TABLE snapshot_meta (key TEXT PRIMARY KEY, value TEXT);
"""


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def structural_chunks(text: str, title: str) -> list[tuple[str, str]]:
    """Keep fenced code intact. Oversized blocks remain clearly marked excerpts in search."""
    chunks: list[tuple[str, str]] = []
    section, buffer, fence = title, [], False
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith(("```", "~~~")):
            fence = not fence
        if not fence and re.match(r"^#{1,6}\s", line):
            if buffer:
                chunks.append((section, "".join(buffer)))
                buffer = []
            section = line.lstrip("#").strip()
        buffer.append(line)
        if not fence and not line.strip() and sum(map(len, buffer)) >= 1400:
            chunks.append((section, "".join(buffer)))
            buffer = []
    if buffer:
        chunks.append((section, "".join(buffer)))
    return [(section, value) for section, value in chunks if value.strip()]


def snapshot_path(data_dir: Path, snapshot_id: str | None = None) -> tuple[str, Path]:
    if snapshot_id is None:
        active = data_dir / "active.json"
        if not active.exists():
            raise KnowledgeError("INDEX_UNAVAILABLE", "Prepare a base antes de consultar.")
        try:
            snapshot_id = json.loads(active.read_text(encoding="utf-8"))["snapshot_id"]
        except (ValueError, KeyError, OSError):
            raise KnowledgeError("INDEX_UNAVAILABLE", "Manifesto ativo inválido.") from None
    if not isinstance(snapshot_id, str) or not re.fullmatch(r"[0-9a-f]{32}", snapshot_id):
        raise KnowledgeError("INVALID_ARGUMENT", "snapshot_id inválido.")
    directory = data_dir / "snapshots" / snapshot_id
    if not (directory / "knowledge.sqlite3").is_file():
        raise KnowledgeError("SNAPSHOT_UNAVAILABLE", "Snapshot não disponível.")
    return snapshot_id, directory


def connect_snapshot(directory: Path) -> sqlite3.Connection:
    db = sqlite3.connect(
        (directory / "knowledge.sqlite3").as_uri() + "?mode=ro", uri=True, check_same_thread=False
    )
    db.row_factory = sqlite3.Row
    return db


def ingest_documents(
    data_dir: Path, documents: list[Document], sources: dict, embedding_mode: str = "lexical"
) -> dict:
    """Replace a complete manifest selection. Old snapshots remain available for cursors."""
    data_dir = Path(data_dir).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    if not documents:
        raise KnowledgeError("INVALID_ARGUMENT", "Não publicar uma seleção vazia.")
    if embedding_mode not in {"lexical", "semantic"}:
        raise KnowledgeError("INVALID_ARGUMENT", "Perfil de indexação inválido.")
    if any(source.get("quarantine") for source in sources.values()):
        raise KnowledgeError(
            "INVALID_ARGUMENT", "Há registros em quarentena; corrija o manifesto antes de publicar."
        )
    with FileLock(str(data_dir / "writer.lock"), timeout=1):
        sid = uuid.uuid4().hex
        directory = data_dir / "snapshots" / sid
        directory.mkdir(parents=True)
        blobs = data_dir / "originals"
        blobs.mkdir(exist_ok=True)
        db = sqlite3.connect(directory / "knowledge.sqlite3")
        db.executescript(SCHEMA)
        seen: set[str] = set()
        embedding = None
        chunks_for_vectors: list[tuple[str, str, str]] = []
        try:
            if embedding_mode == "semantic":
                from .embeddings import LocalEmbedding

                embedding = LocalEmbedding(data_dir)
            for document in documents:
                if document.document_id in seen:
                    raise KnowledgeError("INVALID_ARGUMENT", "Documento duplicado na seleção.")
                seen.add(document.document_id)
                if len(document.raw) > 64 * 1024 * 1024:
                    raise KnowledgeError("INVALID_ARGUMENT", "Documento excede o limite de 64 MiB.")
                hash_value = document.original_hash
                original = blobs / hash_value
                if original.exists():
                    if digest(original.read_bytes()) != hash_value:
                        raise KnowledgeError(
                            "INDEX_UNAVAILABLE", "Original existente não confere com o hash."
                        )
                else:
                    temporary = blobs / (hash_value + "." + uuid.uuid4().hex + ".tmp")
                    with temporary.open("xb") as stream:
                        stream.write(document.raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, original)
                metadata = dict(document.metadata)
                metadata.setdefault("lifecycle_status", "active")
                metadata["entity_ids"] = sorted(
                    set(metadata.get("entity_ids", []))
                    | {entity["entity_id"] for entity in document.entities}
                )
                db.execute(
                    "INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        document.document_id,
                        document.source_id,
                        document.path,
                        document.revision,
                        document.url,
                        document.title,
                        document.content_type,
                        hash_value,
                        json.dumps(metadata, ensure_ascii=False),
                    ),
                )
                for entity in document.entities:
                    db.execute(
                        "INSERT INTO entities VALUES (?,?,?)",
                        (entity["entity_id"], document.document_id, json.dumps(entity, ensure_ascii=False)),
                    )
                for relation in document.relations:
                    values = (
                        relation["subject_id"],
                        relation["predicate"],
                        relation["object_id"],
                        document.document_id,
                        str(relation.get("evidence_locator", document.path)),
                    )
                    relation_id = digest(json.dumps(values).encode())
                    db.execute("INSERT OR IGNORE INTO relations VALUES (?,?,?,?,?,?)", (relation_id, *values))
                if not metadata.get("indexable", True):
                    continue
                for number, (section, text) in enumerate(structural_chunks(document.text, document.title)):
                    cid = digest(f"{document.document_id}:{document.revision}:{number}:{text}".encode())
                    db.execute(
                        "INSERT INTO chunks VALUES (?,?,?,?)",
                        (cid, document.document_id, f"section-{number}", text),
                    )
                    db.execute(
                        "INSERT INTO chunk_fts VALUES (?,?,?)", (cid, document.title + " " + section, text)
                    )
                    if embedding:
                        for part in embedding.passages(text, document.title + " | " + section):
                            chunks_for_vectors.append((cid, document.document_id, part))
            meta = {
                "snapshot_id": sid,
                "published_at": utc_now(),
                "schema_version": "1.0",
                "profile": embedding_mode,
                "sources": sources,
                "document_count": len(seen),
                "chunk_count": db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0],
                "entity_count": db.execute("SELECT COUNT(DISTINCT entity_id) FROM entities").fetchone()[0],
                "model": embedding.manifest if embedding else None,
                "warnings": ["Seleção de fontes limitada; consulte coverage."],
            }
            if not meta["chunk_count"]:
                raise KnowledgeError(
                    "INVALID_ARGUMENT", "Nenhum conteúdo pesquisável; geração ativa preservada."
                )
            if embedding:
                from .embeddings import build_vectors

                build_vectors(directory / "vectors", chunks_for_vectors, embedding)
            db.execute(
                "INSERT INTO snapshot_meta VALUES (?,?)", ("manifest", json.dumps(meta, ensure_ascii=False))
            )
            db.commit()
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise KnowledgeError("INDEX_UNAVAILABLE", "Falha de integridade do snapshot.")
            db.close()
            atomic_json(directory / "manifest.json", meta)
            atomic_json(data_dir / "active.json", {"snapshot_id": sid})
            # active.json is the commit point; a diagnostic write cannot undo a publication.
            try:
                atomic_json(
                    data_dir / "last_ingestion.json",
                    {"status": "published", "snapshot_id": sid, "at": utc_now()},
                )
            except OSError:
                meta["warnings"].append("Snapshot publicado; registro de última ingestão indisponível.")
            return meta
        except Exception:
            db.close()
            atomic_json(
                data_dir / "last_ingestion.json",
                {
                    "status": "failed",
                    "at": utc_now(),
                    "message": "Preparação falhou; geração ativa preservada.",
                },
            )
            raise
