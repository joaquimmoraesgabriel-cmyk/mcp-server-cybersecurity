"""Deterministic retrieval checks, separate from unevaluated client answers.

This module never calls an LLM, imports a corpus or makes a network request.
Only cases with an explicit, verified retrieval oracle are executed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from .models import utc_now

CHECK_KINDS = {"entity", "missing_entity", "raw_document", "relation", "search"}


class _SharedCoreService:
    """Adapt the existing core without taking ownership of its storage or lifetime."""

    def __init__(self, client: Any):
        self.client = client

    def dispatch(self, name: str, arguments: dict) -> dict:
        return self.client.call(name, arguments)

    def close(self) -> None:
        """The shared core remains available to other connected clients."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _positive(response: dict) -> list[dict]:
    _require(response.get("status") in {"ok", "partial"}, "Query did not return usable evidence.")
    results = response.get("results", [])
    _require(bool(results), "Query returned no evidence.")
    _require(bool(response.get("citations")), "Positive evidence has no citations.")
    return results


def _run_case(service: Any, case: dict, snapshot_id: str) -> None:
    def call(name: str, **arguments: Any) -> dict:
        response = service.dispatch(name, {**arguments, "snapshot_id": snapshot_id})
        if response.get("status") != "error":
            _require(response.get("snapshot_id") == snapshot_id, "Snapshot changed during evaluation.")
        return response

    kind = case.get("check", {}).get("kind")
    check = case["check"]
    _require(kind in CHECK_KINDS, "Unsupported deterministic check; not evaluated as a success.")
    if kind in {"entity", "raw_document"}:
        entity_id = check["entity_id"]
        response = call("knowledge_get_entity", entity_id=entity_id)
        results = _positive(response)
        _require(len(results) == 1, "Exact lookup did not return one entity group.")
        _require(results[0].get("entity_id") == entity_id, "Exact entity identity differs.")
        records = results[0].get("records", [])
        source_ids = {record.get("source_id") for record in records}
        _require(set(check.get("required_source_ids", [])).issubset(source_ids), "Required source missing.")
        for source_id, expected in check.get("required_statuses", {}).items():
            _require(any(record.get("source_id") == source_id and record.get("status") == expected
                         for record in records), f"Expected lifecycle state missing for {source_id}.")
        if kind == "entity":
            return
        candidates = [record for record in records if record.get("source_id") == check["source_id"]]
        _require(len(candidates) == 1, "Raw-byte check requires one unambiguous source record.")
        document_id = candidates[0]["document_id"]
        expected_hash = check["expected_sha256"]
        expected_size = check["expected_bytes"]
        assembled = bytearray()
        cursor = None
        seen_cursors: set[str] = set()
        for _ in range(100):
            arguments = {"document_id": document_id}
            if cursor:
                arguments["cursor"] = cursor
            document_response = call("knowledge_get_document", **arguments)
            parts = _positive(document_response)
            _require(len(parts) == 1, "Expected one original part per response.")
            part = parts[0]
            _require(part.get("content_encoding") == "base64", "Expected lossless base64 original.")
            raw = base64.b64decode(part["content"], validate=True)
            _require(part.get("document_id") == document_id, "Original identity changed.")
            _require(part.get("original_hash") == expected_hash, "Original hash differs from fixture.")
            _require(part.get("part_hash") == hashlib.sha256(raw).hexdigest(), "Part hash differs.")
            _require(part.get("total_bytes") == expected_size, "Original byte length differs.")
            _require(part.get("byte_start") == len(assembled), "Original parts are not contiguous.")
            assembled.extend(raw)
            _require(part.get("byte_end") == len(assembled), "Part byte end is inconsistent.")
            cursor = document_response.get("next_cursor")
            if not cursor:
                _require(not document_response.get("truncated"), "Truncated original without continuation.")
                break
            _require(cursor not in seen_cursors, "Repeated original continuation cursor.")
            seen_cursors.add(cursor)
        else:
            raise AssertionError("Original exceeded the evaluation page limit.")
        _require(len(assembled) == expected_size, "Original reconstruction is incomplete.")
        _require(hashlib.sha256(assembled).hexdigest() == expected_hash, "Reconstructed bytes differ.")
    elif kind == "missing_entity":
        response = call("knowledge_get_entity", entity_id=check["entity_id"])
        absent = response.get("status") == "no_results" or (
            response.get("status") == "error" and response.get("error", {}).get("code") == "NOT_FOUND")
        _require(absent, "Missing identity was substituted or absence could not be determined.")
        _require(not response.get("results"), "Missing identity returned evidence for another entity.")
    elif kind == "relation":
        results = _positive(call("knowledge_get_related", entity_id=check["entity_id"], limit=50))
        matching = [result for result in results
                    if all(result.get(field) == check[field]
                           for field in ("subject_id", "predicate", "object_id"))]
        _require(bool(matching), "Expected documented relation missing.")
        _require(all(result.get("evidence_document_id") for result in matching), "Relation lacks evidence.")
    elif kind == "search":
        response = call("knowledge_search", query=check["query"], filters=check.get("filters", {}),
                        limit=check.get("limit", 10))
        results = _positive(response)
        expected_ids = set(check.get("required_entity_ids", []))
        found_ids = {entity_id for result in results for entity_id in result.get("entity_ids", [])}
        _require(expected_ids.issubset(found_ids), "Required entity missing from retrieved documents.")
        required_sources = set(check.get("required_source_ids", []))
        _require(required_sources.issubset({result.get("source_id") for result in results}),
                 "Required source missing from search results.")
        text = "\n".join(passage.get("text", "") for result in results
                         for passage in result.get("passages", [])).casefold()
        for phrase in check.get("required_passage_terms", []):
            _require(phrase.casefold() in text, "Required text is not present in delivered passages.")


def run_checks(data_dir: Path, benchmark_path: Path | None = None, *, use_core: bool = False) -> dict:
    """Check an existing snapshot against an explicit benchmark; never seed data.

    Use ``use_core=True`` when clients may already own the vector storage.
    The default in-process mode requires exclusive access to a test data directory.
    A missing benchmark or an all-unverified roadmap yields ``not_evaluated``.
    A zero denominator is never a passing result or a claim of answer quality.
    """
    report: dict = {
        "schema_version": "1.0", "generated_at": utc_now(), "status": "not_evaluated",
        "snapshot_id": None, "benchmark_version": None, "dataset_kind": None,
        "transport": "shared_core" if use_core else "in_process",
        "summary": {"total": 0, "eligible": 0, "executed": 0, "passed": 0, "failed": 0, "skipped": 0},
        "source_revision_check": {"status": "not_requested", "expected": {}, "actual": {}},
        "cases": [], "by_split": {},
        "not_evaluated": ["GPT/Claude answer fidelity", "client compatibility", "semantic recall",
                          "real corpus coverage", "adversarial instruction resistance"],
        "warnings": ["Passing deterministic retrieval checks does not approve the 30-question client benchmark."],
    }
    if benchmark_path is None:
        report["warnings"].append("An explicit benchmark path is required; no data or oracle was assumed.")
        return report
    benchmark_path = Path(benchmark_path)
    if benchmark_path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Benchmark exceeds 2 MiB.")
    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    if not isinstance(benchmark, dict) or not isinstance(benchmark.get("cases"), list):
        raise TypeError("Benchmark must contain a cases list.")
    cases = benchmark["cases"]
    if len(cases) > 500:
        raise ValueError("Benchmark exceeds 500 cases.")
    ids = [case.get("id") if isinstance(case, dict) else None for case in cases]
    if any(not isinstance(case_id, str) or not case_id for case_id in ids) or len(set(ids)) != len(ids):
        raise ValueError("Benchmark case IDs must be non-empty and unique.")
    expected_revisions = benchmark.get("source_revisions", {})
    if not isinstance(expected_revisions, dict) or any(
        not isinstance(source_id, str) or not source_id or not isinstance(revision, str) or not revision
        for source_id, revision in expected_revisions.items()
    ):
        raise TypeError("source_revisions must map non-empty source IDs to revision strings.")
    if expected_revisions:
        report["source_revision_check"].update(status="not_evaluated", expected=expected_revisions)
    report["benchmark_version"] = benchmark.get("benchmark_version")
    report["dataset_kind"] = benchmark.get("dataset_kind")
    report["summary"]["total"] = len(cases)
    eligible = [case for case in cases if case.get("verification_status") == "verified"]
    report["summary"]["eligible"] = len(eligible)
    for case in cases:
        if case not in eligible:
            report["cases"].append({"id": case["id"], "split": case.get("split", "unspecified"),
                                    "status": "skipped", "reason": "Oracle not verified for this dataset."})
    if eligible:
        if use_core:
            from .runtime import ensure_core

            service = _SharedCoreService(ensure_core(Path(data_dir)))
        else:
            from .service import KnowledgeService

            service = KnowledgeService(Path(data_dir))
        try:
            state = service.dispatch("knowledge_status", {})
            snapshot_id = state.get("snapshot_id")
            status_results = state.get("results") or [{}]
            sources = status_results[0].get("sources", {})
            actual_revisions = {source_id: sources.get(source_id, {}).get("revision")
                                for source_id in expected_revisions}
            revision_mismatches = sorted(source_id for source_id, revision in expected_revisions.items()
                                         if actual_revisions[source_id] != revision)
            if expected_revisions:
                report["source_revision_check"].update(
                    status="failed" if revision_mismatches else "passed", actual=actual_revisions)
            for case in eligible:
                result = {"id": case["id"], "split": case.get("split", "unspecified"),
                          "critical": bool(case.get("critical")), "status": "passed"}
                try:
                    _require(bool(snapshot_id) and state.get("status") in {"ok", "partial"},
                             "No readable snapshot available for evaluation.")
                    _require(not revision_mismatches,
                             "Benchmark source revision mismatch: " + ", ".join(revision_mismatches) + ".")
                    expected_snapshot = case.get("snapshot_id") or benchmark.get("snapshot_id")
                    _require(not expected_snapshot or expected_snapshot == snapshot_id,
                             "Oracle is bound to a different snapshot.")
                    _run_case(service, case, snapshot_id)
                except (AssertionError, KeyError, TypeError, ValueError) as exc:
                    result.update(status="failed", reason=str(exc))
                report["cases"].append(result)
            report["snapshot_id"] = snapshot_id
        finally:
            service.close()
    report["cases"].sort(key=lambda result: ids.index(result["id"]))
    for result in report["cases"]:
        outcome = result["status"]
        report["summary"][outcome] += 1
        group = report["by_split"].setdefault(result["split"], {"passed": 0, "failed": 0, "skipped": 0})
        group[outcome] += 1
    report["summary"]["executed"] = report["summary"]["passed"] + report["summary"]["failed"]
    if report["summary"]["executed"]:
        report["status"] = "failed" if report["summary"]["failed"] else "passed"
    return report
