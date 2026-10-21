"""Read-only MCP cache regression; optionally exercise a disposable memory note.

Run after the per-source online gates have populated the selected data directory.
This does not claim that a whole upstream corpus was indexed.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cyber_rag.source_registry import SOURCES


async def validate(args):
    unknown = set(args.skip) - (set(SOURCES) | {"owasp"})
    if unknown:
        raise ValueError(f"Unknown source IDs: {sorted(unknown)}")
    memory_sources = {"owasp", "attack", "cwe"}
    if args.exercise_memory and memory_sources.intersection(args.skip):
        raise ValueError("The memory test requires OWASP, ATT&CK and CWE samples.")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "cyber_rag", "serve", "--data-dir", str(args.data_dir.resolve())],
        env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
    )
    report = {"checked_at": datetime.now(UTC).isoformat(), "sources": [], "skipped_sources": args.skip}
    async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as session:
        await session.initialize()
        tools = await session.list_tools()
        expected_tools = {
            "knowledge_search",
            "knowledge_get_entity",
            "knowledge_get_document",
            "knowledge_get_related",
            "knowledge_status",
            "knowledge_catalog",
            "knowledge_research",
            "knowledge_get_cached_document",
            "knowledge_remember",
            "knowledge_forget",
        }
        assert {tool.name for tool in tools.tools} == expected_tools

        async def call(name, arguments):
            response = await session.call_tool(name, arguments)
            assert not response.isError, name
            data = response.structuredContent
            assert isinstance(data, dict) and data["status"] != "error", (name, data)
            return data

        status = await call("knowledge_status", {})
        assert status["results"][0]["tool_contract"] == 3
        report.update(
            tool_count=len(tools.tools),
            snapshot_id=status.get("snapshot_id"),
            snapshot_documents=status["results"][0].get("document_count"),
        )
        catalogue = await call("knowledge_catalog", {})
        assert {source["source_id"] for source in catalogue["results"]} == set(SOURCES) | {"owasp"}
        report["configured_sources"] = len(catalogue["results"])
        report["catalog_response_bytes"] = len(json.dumps(catalogue).encode())
        if args.exercise_online:
            report["online_queries"] = []
            for sources, query in [
                (["owasp"], "password storage"),
                (["cve", "kev", "nvd"], "CVE-2021-44228"),
            ]:
                sources = [source for source in sources if source not in args.skip]
                if not sources:
                    continue
                result = await call(
                    "knowledge_research",
                    {
                        "query": query,
                        "source_ids": sources,
                        "freshness": "refresh",
                        "limit": 3,
                    },
                )
                cache = result["layers"]["source_cache"]
                assert set(cache["sources"]) == set(sources)
                assert all(s["remote_status"] == "verified" for s in cache["sources"].values()), cache[
                    "sources"
                ]
                assert {item["source_id"] for item in cache["results"]} == set(sources)
                report["online_queries"].append({"sources": sources, "status": "passed"})
        evidence = {}
        queries = {"owasp": ("armazenamento seguro de senhas", None, "password")}
        queries.update({key: (s.sample_query, s.sample_path, s.expected_text) for key, s in SOURCES.items()})
        for source, (query, path, expected) in queries.items():
            if source in args.skip:
                continue
            arguments = {"query": query, "source_ids": [source], "freshness": "offline", "limit": 1}
            if path:
                arguments["path"] = path
            result = await call("knowledge_research", arguments)
            cache = result["layers"]["source_cache"]
            assert cache["sources"][source]["remote_status"] == "offline", source
            items = cache["results"]
            assert items and items[0]["source_id"] == source, source
            item = items[0]
            assert expected.casefold() in " ".join(p["text"] for p in item["passages"]).casefold(), source
            evidence[source] = item
            report["sources"].append(
                {
                    "source_id": source,
                    "document_id": item["document_id"],
                    "revision": item["revision"],
                    "original_hash": item["original_hash"],
                    "freshness": item["freshness"],
                    "status": "passed",
                }
            )
        report["combined_queries"] = []
        for sources, query in [
            (["attack", "sigma", "atomic-red-team"], "T1059.001 PowerShell"),
            (["cve", "kev", "nvd"], "CVE-2021-44228"),
            (list(evidence), "security authentication"),
        ]:
            sources = [source for source in sources if source in evidence]
            if not sources:
                continue
            result = await call(
                "knowledge_research",
                {
                    "query": query,
                    "source_ids": sources,
                    "freshness": "offline",
                    "limit": 3,
                },
            )
            cache = result["layers"]["source_cache"]
            assert set(cache["sources"]) == set(sources)
            assert all(s["remote_status"] == "offline" for s in cache["sources"].values())
            assert len(cache["results"]) <= 3
            assert cache["results"], sources
            report["combined_queries"].append(
                {"sources": sources, "returned": len(cache["results"]), "status": "passed"}
            )
        report["original_roundtrips"] = []
        for source in ["owasp", "nvd", "exploit-db", "vx-papers"]:
            if source not in evidence:
                continue
            item = evidence[source]
            original, offset, pages = bytearray(), 0, 0
            while True:
                result = await call(
                    "knowledge_get_cached_document",
                    {
                        "document_id": item["document_id"],
                        "revision": item["revision"],
                        "offset": offset,
                    },
                )
                part = result["results"][0]
                original.extend(base64.b64decode(part["content"], validate=True))
                pages += 1
                assert pages < 2000, "Unexpectedly large validation document"
                if part["last_part"]:
                    break
                offset = part["next_offset"]
            assert hashlib.sha256(original).hexdigest() == item["original_hash"], source
            report["original_roundtrips"].append(
                {"source_id": source, "bytes": len(original), "pages": pages, "status": "passed"}
            )
        if args.exercise_memory:
            test_marker = uuid.uuid4().hex
            saved = await call(
                "knowledge_remember",
                {
                    "text": f"Validação descartável multifontes {test_marker}: conferir evidências de senha, técnica e fraqueza.",
                    "references": [evidence[key]["evidence_reference"] for key in ["owasp", "attack", "cwe"]],
                    "ttl_days": 1,
                },
            )
            memory_id = saved["results"][0]["memory_id"]
            try:
                result = await call(
                    "knowledge_research",
                    {
                        "query": test_marker,
                        "freshness": "offline",
                        "source_ids": ["owasp", "attack", "cwe"],
                        "limit": 3,
                    },
                )
                assert any(r["memory_id"] == memory_id for r in result["layers"]["memory"]["results"])
            finally:
                erased = await call("knowledge_forget", {"memory_id": memory_id})
                assert erased["results"][0]["deleted"]
            report["memory_roundtrip"] = "passed_and_test_note_deleted"
    report["status"] = "passed"
    report["limitations"] = [
        "Offline cache and MCP transport regression; upstream online gates are reported separately.",
        "Selection smoke tests do not measure full corpus coverage or client answer quality.",
        "Claude application was not exercised by this script.",
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {"status": report["status"], "sources": len(report["sources"]), "report": str(args.report)},
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--skip", action="append", default=[], help="Explicit unavailable source ID")
    parser.add_argument("--exercise-memory", action="store_true")
    parser.add_argument(
        "--exercise-online",
        action="store_true",
        help="Also revalidate OWASP and the CVE/KEV/NVD group via their URLs",
    )
    asyncio.run(validate(parser.parse_args()))
