"""Sequential live URL, local cache and offline regression smoke tests.

Use a dedicated data directory first. This fetches the configured sample for
each connector, not the entire upstream corpus. Unavailable sources must be
explicitly excluded and reported separately; nothing is silently marked passed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import make_adapter
from cyber_rag.source_registry import SOURCES


def validate(args):
    unknown = set(args.source + args.skip) - set(SOURCES)
    if unknown:
        raise ValueError(f"Unknown source IDs: {sorted(unknown)}")
    source_ids = args.source or list(SOURCES)
    report = {
        "started_at": datetime.now(UTC).isoformat(),
        "sources": [],
        "skipped_sources": args.skip,
        "status": "running",
    }

    def save():
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    def no_network(*_args, **_kwargs):
        raise AssertionError("Offline regression attempted network access")

    for source_id in source_ids:
        if source_id in args.skip:
            continue
        spec = SOURCES[source_id]
        adapter = make_adapter(spec)
        calls = []
        actual_fetch = adapter.fetcher

        def record(url, _calls=calls, _fetch=actual_fetch, **kwargs):
            _calls.append(url)
            return _fetch(url, **kwargs)

        adapter.fetcher = record
        store = RemoteStore(args.data_dir, adapter)
        started = time.monotonic()
        result = store.research(spec.sample_query, freshness="auto", limit=1, path=spec.sample_path)
        items = result["results"]
        if not items or items[0]["freshness"] != "current":
            report.update(status="failed", failed_source=source_id, failure=result)
            save()
            raise AssertionError(f"Live source gate failed: {source_id}; see {args.report}")
        item = items[0]
        assert spec.expected_text.casefold() in " ".join(p["text"] for p in item["passages"]).casefold(), (
            source_id
        )
        page = store.get_document(item["document_id"], item["revision"])
        assert page["original_hash"] == item["original_hash"], source_id
        online_calls = len(calls)
        reused = store.research(spec.sample_query, freshness="auto", limit=1, path=spec.sample_path)
        assert (
            len(calls) == online_calls and reused["results"][0]["original_hash"] == item["original_hash"]
        ), source_id
        report["sources"].append(
            {
                "source_id": source_id,
                "status": "passed",
                "query": spec.sample_query,
                "path": item["path"],
                "revision": item["revision"],
                "original_hash": item["original_hash"],
                "checked_at": item["checked_at"],
                "original_bytes": page["total_bytes"],
                "known_paths": result["catalog"]["known_paths"],
                "remote_calls": online_calls,
                "cache_reuse_passed": True,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        )
        # After each source, check every preceding source without any network.
        for earlier in report["sources"]:
            other = SOURCES[earlier["source_id"]]
            offline_store = RemoteStore(args.data_dir, make_adapter(other, fetcher=no_network))
            offline = offline_store.research(
                other.sample_query, freshness="offline", limit=1, path=other.sample_path
            )
            assert (
                offline["results"] and offline["results"][0]["original_hash"] == earlier["original_hash"]
            ), other.source_id
            earlier["offline_passed"] = True
        report["sources"][-1]["prior_sources_regression"] = len(report["sources"])
        save()
        print(
            json.dumps({"source_id": source_id, "status": "passed", "remote_calls": online_calls}), flush=True
        )
    report.update(status="passed", completed_at=datetime.now(UTC).isoformat())
    report["limitations"] = [
        "Sample retrieval smoke tests; not full corpus ingestion or a relevance benchmark.",
        "OWASP's original adapter and MCP transport are exercised by validate_multisource.py.",
        "auto reuses a current cache; remote_calls records whether a new URL request was needed.",
    ]
    save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--skip", action="append", default=[])
    validate(parser.parse_args())
