"""Explicit local administration and bounded evidence research."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .config import resolve_data_dir
from .models import KnowledgeError


def _emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="cyber-rag", description="RAG local de cibersegurança via MCP")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in (
        "serve",
        "core",
        "status",
        "doctor",
        "config",
        "search",
        "research",
        "catalog",
        "import",
        "sync-pilot",
        "models",
        "evaluate",
    ):
        command = commands.add_parser(name)
        command.add_argument("--data-dir", type=Path, help="Diretório local da base (ou CYBER_RAG_DATA_DIR)")
        if name == "core":
            command.add_argument("--keep-alive", action="store_true", help="Manter núcleo em primeiro plano até Ctrl+C, sem saída por inatividade")
            command.add_argument("--warmup", action="store_true", help="Preparar modelo e índice antes de aceitar consultas")
        if name == "import":
            command.add_argument("manifest", type=Path)
        if name in {"import", "sync-pilot"}:
            command.add_argument("--profile", choices=("lexical", "semantic"), default="lexical")
        if name == "sync-pilot":
            command.add_argument("--destination", type=Path, help="Pasta local para snapshots das fontes")
        if name in {"search", "research"}:
            command.add_argument("query")
            command.add_argument("--limit", type=int, default=3 if name == "research" else 5)
            command.add_argument("--source", action="append")
        if name == "research":
            command.add_argument("--freshness", choices=("auto", "refresh", "offline"), default="auto")
            command.add_argument("--path", help="Caminho exato cheatsheets/*.md cadastrado na OWASP")
        if name == "config":
            command.add_argument("--client", choices=("codex", "claude"), required=True)
        if name == "models":
            command.add_argument("action", choices=("prepare",))
            command.add_argument("--revision", help="Commit do modelo; omissão fixa o commit atual")
        if name == "evaluate":
            command.add_argument("--benchmark", type=Path)
            command.add_argument("--output", type=Path)
            command.add_argument("--split", choices=("development", "acceptance", "smoke"))
    args = parser.parse_args(argv)
    data_dir = resolve_data_dir(args.data_dir)
    try:
        if args.command == "core":
            from .runtime import serve_core

            serve_core(data_dir, keep_alive=args.keep_alive, warmup=args.warmup)
        elif args.command == "serve":
            from .mcp_server import run_stdio

            run_stdio(data_dir)
        elif args.command == "config":
            entry = {
                "command": str(Path(sys.executable).resolve()),
                "args": ["-m", "cyber_rag", "serve", "--data-dir", str(data_dir)],
            }
            source_root = Path(__file__).resolve().parent.parent
            if source_root.name == "src":
                entry["env"] = {"PYTHONPATH": str(source_root)}
            if args.client == "claude":
                _emit({"mcpServers": {"cyber-rag": entry}})
            else:
                print("[mcp_servers.cyber-rag]")
                print("command = " + json.dumps(entry["command"]))
                print("args = " + json.dumps(entry["args"]))
                print("tool_timeout_sec = 150")
                if "env" in entry:
                    print("[mcp_servers.cyber-rag.env]")
                    print("PYTHONPATH = " + json.dumps(entry["env"]["PYTHONPATH"]))
        elif args.command == "doctor":
            import importlib.metadata

            db = sqlite3.connect(":memory:")
            try:
                db.execute("CREATE VIRTUAL TABLE fts_probe USING fts5(content)")
                fts = True
            finally:
                db.close()
            packages = {}
            for name in ("mcp", "PyYAML", "filelock", "qdrant-client", "sentence-transformers"):
                try:
                    packages[name] = importlib.metadata.version(name)
                except importlib.metadata.PackageNotFoundError:
                    packages[name] = None
            _emit(
                {
                    "version": __version__,
                    "python": sys.version.split()[0],
                    "fts5": fts,
                    "packages": packages,
                    "data_dir": str(data_dir),
                    "active_snapshot": (data_dir / "active.json").is_file(),
                    "model_prepared": (data_dir / "model.json").is_file(),
                    "network_checks": "not_performed",
                }
            )
        elif args.command in {"import", "sync-pilot"}:
            from .ingestion import load_manifest
            from .snapshot import ingest_documents

            if args.command == "sync-pilot":
                from .sources import fetch_pilot

                manifest_path = fetch_pilot(args.destination or data_dir / "imports")
            else:
                manifest_path = args.manifest
            documents, sources = load_manifest(manifest_path)
            _emit(ingest_documents(data_dir, documents, sources, args.profile))
        elif args.command == "models":
            from .embeddings import prepare_model

            _emit(prepare_model(data_dir, args.revision))
        elif args.command == "evaluate":
            from .evaluation import run_checks

            report = run_checks(data_dir, args.benchmark, use_core=True, split=args.split)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(
                    json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            _emit(report)
            return 1 if report["status"] == "failed" else 2 if report["status"] == "not_evaluated" else 0
        else:
            from .runtime import ensure_core

            client = ensure_core(data_dir)
            if args.command == "status":
                result = client.call("knowledge_status", {})
            elif args.command == "catalog":
                result = client.call("knowledge_catalog", {})
            elif args.command == "research":
                result = client.call("knowledge_research", {"query": args.query, "limit": args.limit,
                                     "source_ids": args.source, "freshness": args.freshness, "path": args.path})
            else:
                result = client.call(
                    "knowledge_search",
                    {
                        "query": args.query,
                        "limit": args.limit,
                        "filters": {"source_ids": args.source} if args.source else {},
                    },
                )
            _emit(result)
            return 1 if result.get("status") == "error" else 0
        return 0
    except (KnowledgeError, ValueError, TypeError, OSError, ImportError, RuntimeError) as exc:
        # Admin errors go to stderr. No query, credential or source content is logged.
        print(
            json.dumps(
                {"status": "error", "code": getattr(exc, "code", "ADMIN_ERROR"), "message": str(exc)},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
