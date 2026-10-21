"""Verify honest evaluation accounting and retrieval against isolated fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyber_rag.evaluation import _run_case, run_checks
from cyber_rag.ingestion import load_manifest
from cyber_rag.models import Document
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


def test_benchmark_content_digest_survives_git_line_ending_conversion(tmp_path):
    content = json.dumps({"cases": [], "description": "avaliação"}, ensure_ascii=False, indent=2)
    lf, crlf = tmp_path / "lf.json", tmp_path / "crlf.json"
    lf.write_bytes(content.encode("utf-8"))
    crlf.write_bytes(content.replace("\n", "\r\n").encode("utf-8"))
    first, second = run_checks(tmp_path / "absent", lf), run_checks(tmp_path / "absent", crlf)
    assert first["benchmark_sha256"] != second["benchmark_sha256"]
    assert first["benchmark_content_sha256"] == second["benchmark_content_sha256"]


def test_retrieval_matrix_preserves_all_questions_and_marks_client_gaps():
    roadmap = json.loads(QUESTIONS.read_text(encoding="utf-8"))["cases"]
    matrix = json.loads(QUESTIONS.with_name("retrieval.json").read_text(encoding="utf-8"))["cases"]
    assert [{key: case[key] for key in ("id", "question", "split", "critical")} for case in matrix] == [
        {key: case[key] for key in ("id", "question", "split", "critical")} for case in roadmap]
    assert {case["id"] for case in matrix if case["verification_status"] != "verified"} == {
        "Q21", "Q22", "Q27", "Q28", "Q29", "Q30"}
    assert all(case["client_answer_status"] == "not_evaluated" for case in matrix)


@pytest.mark.parametrize("checks", [[], [{}], [None], [{"kind": "unknown"}]])
def test_empty_or_unsupported_checks_cannot_pass(fixture_data_dir, tmp_path, checks):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"cases": [{"id": "bad", "verification_status": "verified",
                                         "checks": checks}]}), encoding="utf-8")
    report = run_checks(fixture_data_dir, path)
    assert report["summary"]["failed"] == 1
    assert report["cases"][0]["checks_completed"] == 0


def test_composite_checks_and_split_do_not_run_acceptance(fixture_data_dir, tmp_path):
    valid = json.loads((FIXTURES / "smoke.json").read_text(encoding="utf-8"))["cases"][0]["check"]
    path = tmp_path / "split.json"
    path.write_text(json.dumps({"cases": [
        {"id": "dev", "split": "development", "verification_status": "verified", "checks": [valid, valid]},
        {"id": "held", "split": "acceptance", "verification_status": "verified", "checks": [{}]},
    ]}), encoding="utf-8")
    report = run_checks(fixture_data_dir, path, split="development")
    assert report["summary"]["total"] == report["summary"]["passed"] == 1
    assert report["cases"][0]["checks_completed"] == 2
    assert report["client_answer_status"] == "not_evaluated"


class Responses:
    def __init__(self, responses):
        self.responses = iter(responses)

    def dispatch(self, name, arguments):
        return next(self.responses)


def test_search_term_in_wrong_document_cannot_satisfy_oracle():
    response = {"status": "ok", "snapshot_id": "test", "results": [
        {"document_id": "target", "passages": [{"section_id": "s0", "text": "Only a title"}]},
        {"document_id": "other", "passages": [{"section_id": "s1", "text": "Argon2id"}]},
    ], "citations": [{"document_id": "target", "section_id": "s0", "url": "https://example.org",
                      "revision": "test-v1", "original_hash": "a" * 64}]}
    check = {"kind": "search", "query": "passwords", "required_documents": [
        {"document_id": "target", "passage_terms": ["Argon2id"]}]}
    with pytest.raises(AssertionError, match="target document"):
        _run_case(Responses([response]), {"check": check}, "test")
    response["results"][0]["passages"][0]["text"] = "Use Argon2id"
    response["citations"][0]["section_id"] = "wrong-section"
    with pytest.raises(AssertionError, match="citation"):
        _run_case(Responses([response]), {"check": check}, "test")


@pytest.mark.parametrize("last", [
    {"status": "error", "error": {"code": "TIMEOUT"}},
    {"status": "ok", "results": [{"subject_id": "cve:X", "object_id": "sigma:Y"}]},
])
def test_negative_relation_requires_all_pages_and_no_errors(last):
    first = {"status": "partial", "snapshot_id": "test", "results": [], "next_cursor": "page2"}
    last = {"snapshot_id": "test", **last}
    with pytest.raises(AssertionError):
        _run_case(Responses([first, last]), {"check": {"kind": "no_relation", "entity_id": "cve:X",
                                                     "target_prefix": "sigma:"}}, "test")


def test_wrong_field_assertion_fails_after_successful_entity_lookup(fixture_data_dir, tmp_path):
    valid = json.loads((FIXTURES / "smoke.json").read_text(encoding="utf-8"))["cases"][0]["check"]
    valid["required_record_values"] = [{"source_id": "attack", "path": ["name"], "equals": "WRONG"}]
    path = tmp_path / "wrong-field.json"
    path.write_text(json.dumps({"cases": [{"id": "wrong", "verification_status": "verified",
                                         "check": valid}]}), encoding="utf-8")
    report = run_checks(fixture_data_dir, path)
    assert report["status"] == "failed"
    assert "field differs" in report["cases"][0]["reason"]


def test_direct_original_reconstructs_pages_before_asserting_json(tmp_path):
    raw = json.dumps({"padding": "x" * 21000, "versions": [{"status": "affected"}]}).encode()
    document = Document("cve", "record.json", "test-v1", "https://example.org/record",
                        "Test record", "application/json", raw.decode(), raw)
    data_dir = tmp_path / "base"
    ingest_documents(data_dir, [document], {"cve": {"revision": "test-v1"}})
    check = {"kind": "raw_document", "document_id": document.document_id,
             "expected_sha256": document.original_hash, "expected_bytes": len(raw),
             "required_json_values": [{"path": ["versions", 0, "status"], "equals": "affected"}]}
    path = tmp_path / "direct-original.json"
    benchmark = {"cases": [{"id": "raw", "verification_status": "verified", "check": check}]}
    path.write_text(json.dumps(benchmark), encoding="utf-8")
    assert run_checks(data_dir, path)["status"] == "passed"
    check["required_json_values"][0]["equals"] = "unaffected"
    path.write_text(json.dumps(benchmark), encoding="utf-8")
    assert run_checks(data_dir, path)["status"] == "failed"


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
