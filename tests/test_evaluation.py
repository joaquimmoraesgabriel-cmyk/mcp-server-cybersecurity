"""Verify honest evaluation accounting and retrieval against isolated fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyber_rag.evaluation import run_checks
from cyber_rag.ingestion import load_manifest
from cyber_rag.snapshot import ingest_documents

FIXTURES = Path(__file__).parent / "fixtures"
QUESTIONS = Path(__file__).parent.parent / "evaluations" / "questions.json"


@pytest.fixture(scope="module")
def fixture_data_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    data_dir = tmp_path_factory.mktemp("evaluation-corpus")
    documents, sources = load_manifest(FIXTURES / "sources.json")
    ingest_documents(data_dir, documents, sources, embedding_mode="lexical")
    return data_dir


def test_planned_questions_do_not_claim_a_pass_without_oracles(tmp_path: Path) -> None:
    roadmap = json.loads(QUESTIONS.read_text(encoding="utf-8"))
    cases = roadmap["cases"]
    assert [case["id"] for case in cases] == [f"Q{i:02}" for i in range(1, 31)]
    assert sum(case["split"] == "development" for case in cases) == 15
    assert sum(case["split"] == "acceptance" for case in cases) == 15
    assert {case["id"] for case in cases if case["critical"]} == {
        "Q06", "Q08", "Q11", "Q21", "Q22", "Q23", "Q26", "Q28", "Q29", "Q30"
    }
    report = run_checks(tmp_path / "unprepared", QUESTIONS)
    assert report["status"] == "not_evaluated"
    assert report["summary"] == {
        "total": 30, "eligible": 0, "executed": 0, "passed": 0, "failed": 0, "skipped": 30
    }
    assert not (tmp_path / "unprepared").exists()


def test_no_benchmark_does_not_assume_test_data(tmp_path: Path) -> None:
    report = run_checks(tmp_path / "absent")
    assert report["status"] == "not_evaluated"
    assert report["summary"]["executed"] == 0
    assert not (tmp_path / "absent").exists()


def test_verified_fixture_smoke_checks(fixture_data_dir: Path) -> None:
    report = run_checks(fixture_data_dir, FIXTURES / "smoke.json")
    assert report["status"] == "passed", report
    assert report["summary"] == {
        "total": 10, "eligible": 10, "executed": 10, "passed": 10, "failed": 0, "skipped": 0
    }
    assert report["dataset_kind"] == "synthetic_test_fixture"
    assert "GPT/Claude answer fidelity" in report["not_evaluated"]


def test_incorrect_oracle_is_a_failure(fixture_data_dir: Path, tmp_path: Path) -> None:
    benchmark = json.loads((FIXTURES / "smoke.json").read_text(encoding="utf-8"))
    case = next(case for case in benchmark["cases"] if case["id"] == "S06")
    case["check"]["expected_sha256"] = "0" * 64
    benchmark["cases"] = [case]
    path = tmp_path / "wrong-oracle.json"
    path.write_text(json.dumps(benchmark), encoding="utf-8")
    report = run_checks(fixture_data_dir, path)
    assert report["status"] == "failed"
    assert report["summary"]["failed"] == 1
    assert "hash" in report["cases"][0]["reason"].lower()


def test_oracle_for_another_snapshot_is_a_failure(fixture_data_dir: Path, tmp_path: Path) -> None:
    benchmark = json.loads((FIXTURES / "smoke.json").read_text(encoding="utf-8"))
    benchmark["cases"] = benchmark["cases"][:1]
    benchmark["snapshot_id"] = "0" * 32
    path = tmp_path / "wrong-snapshot.json"
    path.write_text(json.dumps(benchmark), encoding="utf-8")
    report = run_checks(fixture_data_dir, path)
    assert report["status"] == "failed"
    assert report["summary"]["executed"] == 1
    assert "different snapshot" in report["cases"][0]["reason"]


def test_duplicate_benchmark_ids_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps({"cases": [{"id": "Q01"}, {"id": "Q01"}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="unique"):
        run_checks(tmp_path, path)


@pytest.mark.parametrize("source_revisions", [
    {"attack": "different-upstream-revision"},
    {"source-not-in-snapshot": "synthetic-test-fixture-v1"},
])
def test_source_revision_mismatch_fails_before_retrieval(
    fixture_data_dir: Path, tmp_path: Path, source_revisions: dict
) -> None:
    benchmark = json.loads((FIXTURES / "smoke.json").read_text(encoding="utf-8"))
    benchmark["cases"] = benchmark["cases"][:1]
    benchmark["source_revisions"] = source_revisions
    # Invalid check would produce a different error if retrieval ran before the revision gate.
    benchmark["cases"][0]["check"] = {"kind": "not-a-retrieval-check"}
    path = tmp_path / "wrong-revisions.json"
    path.write_text(json.dumps(benchmark), encoding="utf-8")
    report = run_checks(fixture_data_dir, path)
    assert report["status"] == "failed"
    assert report["source_revision_check"]["status"] == "failed"
    assert report["summary"]["failed"] == 1
    assert "source revision mismatch" in report["cases"][0]["reason"]


def test_revision_oracle_survives_reindex_with_new_snapshot(fixture_data_dir: Path, tmp_path: Path) -> None:
    benchmark = json.loads((FIXTURES / "smoke.json").read_text(encoding="utf-8"))
    benchmark["cases"] = benchmark["cases"][:1]
    benchmark["snapshot_id"] = None
    benchmark["source_revisions"] = {"attack": "synthetic-test-fixture-v1"}
    path = tmp_path / "portable-oracle.json"
    path.write_text(json.dumps(benchmark), encoding="utf-8")
    before = run_checks(fixture_data_dir, path)
    documents, sources = load_manifest(FIXTURES / "sources.json")
    rebuilt = tmp_path / "rebuilt-data"
    ingest_documents(rebuilt, documents, sources, embedding_mode="lexical")
    after = run_checks(rebuilt, path)
    assert before["snapshot_id"] != after["snapshot_id"]
    assert before["status"] == after["status"] == "passed"
    assert after["source_revision_check"]["status"] == "passed"
