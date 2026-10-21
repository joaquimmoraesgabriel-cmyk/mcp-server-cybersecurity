from dataclasses import replace

import pytest

from cyber_rag import remote_cache
from cyber_rag.ondemand import FetchResponse
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import PublicAdapter
from cyber_rag.source_registry import SOURCES


@pytest.mark.parametrize("external, expected", [(None, 190), (200, 190), (110, 110)])
def test_iso_budget_is_ninety_seconds_and_never_extends_shared_deadline(tmp_path, monkeypatch, external, expected):
    monkeypatch.setattr(remote_cache.time, "monotonic", lambda: 100)
    seen = []

    def fetch(url, **kwargs):
        seen.append(kwargs["deadline"])
        return FetchResponse(200, b"id,reference\n1,ISO/IEC 27001:2022\n")

    store = RemoteStore(tmp_path, PublicAdapter(SOURCES["iso27001"], fetcher=fetch))
    assert store.research("ISO 27001", deadline=external)["results"]
    assert seen == [expected]
    assert store.catalog()["request_budget_seconds"] == 90


@pytest.mark.parametrize("budget", [True, 0, -1, 91, "60", float("inf"), float("nan")])
def test_invalid_adapter_budget_rejected(tmp_path, budget):
    adapter = PublicAdapter(replace(SOURCES["iso27001"], request_budget_seconds=budget))
    with pytest.raises(ValueError, match="request budget"):
        RemoteStore(tmp_path, adapter)


def test_other_public_sources_keep_thirty_second_budget(tmp_path):
    adapter = PublicAdapter(replace(SOURCES["iso27001"], request_budget_seconds=30))
    assert RemoteStore(tmp_path, adapter).catalog()["request_budget_seconds"] == 30
