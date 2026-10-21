"""Reviewed source registry. Entries describe coverage, not arbitrary fetch permissions."""

from .source_registry import SOURCES
from .sources import PILOT_SOURCES

SUBJECTS = {
    "attack": ["adversary techniques", "tactics", "platforms", "mitigations"],
    "owasp": ["application security", "passwords", "injection", "authentication"],
    "sigma": ["detection rules", "log sources", "false positives"],
    "cve": ["vulnerability records", "affected products", "CNA assertions"],
    "kev": ["known exploited vulnerabilities", "CISA remediation deadlines"],
}


def source_catalog():
    catalog = [
        {
            "source_id": spec["source_id"],
            "repository": f"https://github.com/{spec['repository']}",
            "branch": spec["branch"],
            "subjects": SUBJECTS[spec["source_id"]],
            "mode": "on_demand_and_snapshot" if spec["source_id"] == "owasp" else "snapshot_only",
            "discovery": "pinned cheatsheets directory; local path matching"
            if spec["source_id"] == "owasp"
            else "explicit local import",
            "paths": ["cheatsheets/*.md"] if spec["source_id"] == "owasp" else spec["files"],
            "freshness_seconds": 86400 if spec["source_id"] in {"owasp", "cve", "kev"} else 604800,
            "coverage": "retrieved files only; directory listing is not indexed document content"
            if spec["source_id"] == "owasp"
            else spec["selection_policy"],
        }
        for spec in PILOT_SOURCES
    ]
    for source_id, spec in SOURCES.items():
        catalog = [entry for entry in catalog if entry["source_id"] != source_id]
        catalog.append({"source_id": source_id, "title": spec.title,
                        "repository": spec.homepage or "https://github.com/" + spec.repository,
                        "branch": spec.branch, "subjects": list(spec.subjects),
                        "mode": "on_demand_and_snapshot" if source_id in SUBJECTS else "on_demand_and_local_cache", "discovery": spec.discovery,
                        "paths": list(spec.paths or spec.prefixes), "format": spec.format,
                        "freshness_seconds": spec.ttl_seconds, "access_note": spec.access_note,
                        "entrypoints": [url for _, url in spec.urls] or ([spec.url_template] if spec.url_template else [spec.homepage or "https://github.com/" + spec.repository]),
                        "query_requirement": "exact " + spec.id_kind + " identifier" if spec.id_kind else "exact CVE identifier" if spec.discovery == "cve" else "path/topic matching within the registered source",
                        "example_query": spec.sample_query,
                        "coverage": "Only retrieved files are locally indexed; inspect cache counts."})
    return catalog
