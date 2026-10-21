import pytest

from cyber_rag.ondemand import RemoteError
from cyber_rag.source_adapters import PublicAdapter, normalize
from cyber_rag.source_registry import SOURCES


def test_lgpd_requires_identity_and_excludes_old_struck_text():
    body = "<html><body>LEI 13.709 Dados pessoais Art. 1º " + "Texto atualizado da norma. " * 5 + "<s>OLD_CLAUSE</s></body></html>"
    text, metadata = normalize(body.encode(), "lgpd")
    assert "OLD_CLAUSE" not in text
    assert metadata["document_identity"] == "Brazil Law 13.709/2018"
    with pytest.raises(RemoteError, match="invalid_lgpd_document"):
        normalize(("<p>" + "Unrelated legislative document. " * 10 + "</p>").encode(), "lgpd")


def test_lgpd_only_approved_official_updated_text():
    adapter = PublicAdapter(SOURCES["lgpd"])
    assert adapter.allowed(SOURCES["lgpd"].urls[0][1])
    assert not adapter.allowed(SOURCES["lgpd"].urls[0][1] + "?redirect=http://localhost")


def test_gdpr_requires_regulation_identity_and_final_article():
    raw = b"<html><body>Regulation (EU) 2016/679 Article 1 " + b"Personal data protection. " * 5 + b"Article 99</body></html>"
    text, metadata = normalize(raw, "gdpr")
    assert "Article 99" in text
    assert metadata["authority"] == "EU Publications Office Cellar"
    with pytest.raises(RemoteError, match="invalid_gdpr_document"):
        normalize(raw.replace(b"Article 99", b"Truncated"), "gdpr")


def test_gdpr_original_and_consolidation_are_distinct_exact_urls():
    adapter = PublicAdapter(SOURCES["gdpr"])
    assert len(SOURCES["gdpr"].urls) == 2
    for _, url in SOURCES["gdpr"].urls:
        assert adapter.allowed(url)
        assert not adapter.allowed(url.replace("DOC_1", "DOC_2"))
