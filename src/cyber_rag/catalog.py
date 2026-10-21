"""Reviewed source registry. Entries describe coverage, not arbitrary fetch permissions."""

from .sources import PILOT_SOURCES

SUBJECTS = {
    "attack": ["adversary techniques", "tactics", "platforms", "mitigations"],
    "owasp": ["application security", "passwords", "injection", "authentication"],
    "sigma": ["detection rules", "log sources", "false positives"],
    "cve": ["vulnerability records", "affected products", "CNA assertions"],
    "kev": ["known exploited vulnerabilities", "CISA remediation deadlines"],
}


def source_catalog():
    return [
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
