"""Read source snapshots as data only, preserving provenance and original bytes.

These adapters validate supported shapes, not the full upstream JSON schemas.
Unsupported records are reported in quarantine and are never searchable evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import yaml

from .models import Document

PARSER_VERSION = "1.0"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_YAML_BYTES = 2 * 1024 * 1024
MAX_FILES = 20_000
SOURCE_ALIASES = {
    "attack": "attack", "mitre-attack": "attack",
    "owasp": "owasp", "owasp-cheatsheets": "owasp",
    "sigma": "sigma", "cve": "cve", "cve-project": "cve",
    "kev": "kev", "cisa-kev": "kev", "nvd": "nvd",
}
CVE_SCHEMAS = {"5.0", "5.1", "5.1.1", "5.2", "5.2.0"}
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
ATTACK_ID = re.compile(r"(?:T\d{4}(?:\.\d{3})?|TA\d{4}|[GSMC]\d{4}|DS\d{4}|DC\d{4}|DET\d{4}|AN\d{4})")


class IngestionError(ValueError):
    """A source or manifest could not be accepted safely."""


class UnsupportedFormat(IngestionError):
    """The format is recognized but is outside this adapter's support."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise IngestionError("Duplicate mapping key")
        result[key] = value
    return result


def _json(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(IngestionError("Non-finite JSON number")))
        if not isinstance(value, dict):
            raise IngestionError("Expected a JSON object")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise IngestionError("Invalid or excessively nested JSON") from exc


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def _entity(entity_id: str, entity_type: str, name: str, attributes: dict, status: str) -> dict:
    return {"entity_id": entity_id, "entity_type": entity_type, "name": name,
            "attributes": attributes, "status": status}


def _relation(subject: str, predicate: str, target: str, locator: str) -> dict:
    return {"subject_id": subject, "predicate": predicate, "object_id": target,
            "evidence_locator": locator}


def _metadata(**kwargs: Any) -> dict:
    return {"parser_version": PARSER_VERSION, "entity_ids": [], "platforms": [],
            "domains": [], "lifecycle_status": "current", **kwargs}


def _archive(source: str, path: str, revision: str, url: str, raw: bytes, **meta: Any) -> Document:
    return Document(source_id=source, path=path, revision=revision, url=url,
                    title=f"Original source: {path}",
                    content_type="text/plain" if meta.get("record_purpose") == "license_notice" else "application/json", text="", raw=raw,
                    metadata=_metadata(record_kind="source_archive", indexable=False, **meta))


def _attack_identity(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        external = ref.get("external_id", "")
        if ref.get("source_name") in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"} and ATTACK_ID.fullmatch(external):
            return f"attack:{external}"
    return f"stix:{obj['id']}"


def _attack(source: str, path: str, raw: bytes, revision: str, url: str,
            include_entities: list[str] | None = None) -> list[Document]:
    data = _json(raw)
    is_bundle = data.get("type") == "bundle"
    objects = data.get("objects") if is_bundle else [data]
    if not isinstance(objects, list) or len(objects) > 100_000:
        raise IngestionError("STIX bundle needs a bounded objects array")
    known_types = {"attack-pattern", "relationship", "intrusion-set", "malware", "tool",
                   "course-of-action", "campaign", "identity", "marking-definition",
                   "x-mitre-tactic", "x-mitre-matrix", "x-mitre-data-source", "x-mitre-data-component",
                   "x-mitre-collection", "x-mitre-detection-strategy", "x-mitre-analytic", "x-mitre-log-source"}
    identity_map: dict[str, str] = {}
    valid: list[tuple[int, dict]] = []
    quarantine = []
    seen = set()
    for index, obj in enumerate(objects):
        reason = None
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
            reason = "STIX object requires an id"
        elif obj.get("spec_version") != "2.1":
            reason = "Only STIX 2.1 objects are supported"
        elif obj.get("type") not in known_types:
            reason = "Unsupported STIX object type"
        elif obj["id"] in seen:
            reason = "Duplicate STIX id in one bundle"
        if reason:
            quarantine.append({"locator": f"/objects/{index}", "reason": reason})
            continue
        seen.add(obj["id"])
        try:
            identity_map[obj["id"]] = _attack_identity(obj)
        except (TypeError, AttributeError):
            quarantine.append({"locator": f"/objects/{index}", "reason": "Invalid external_references"})
            continue
        valid.append((index, obj))
    docs = [_archive(source, path, revision, url, raw, quarantine=quarantine, excluded_count=0)] if is_bundle else []
    if include_entities is not None:
        missing = sorted(set(include_entities) - set(identity_map.values()))
        if missing:
            quarantine.append({"locator": "/objects", "reason": "Selected ATT&CK entity IDs are absent", "entity_ids": missing})
    for index, obj in valid:
        entity_id = identity_map[obj["id"]]
        state = "revoked" if obj.get("revoked") else "deprecated" if obj.get("x_mitre_deprecated") else "current"
        locator = f"/objects/{index}" if is_bundle else "/"
        relations = []
        entities = []
        entity_ids = [entity_id]
        if obj["type"] == "relationship":
            if not all(isinstance(obj.get(key), str) for key in ("source_ref", "target_ref", "relationship_type")):
                quarantine.append({"locator": locator, "reason": "Incomplete STIX relationship"})
                continue
            subject = identity_map.get(obj["source_ref"], f"stix:{obj['source_ref']}")
            target = identity_map.get(obj["target_ref"], f"stix:{obj['target_ref']}")
            relations = [_relation(subject, obj["relationship_type"], target, locator)]
            entity_ids = [subject, target]
            title = f"{subject} {obj['relationship_type']} {target}"
        else:
            title = obj.get("name", obj["id"])
            entities = [_entity(entity_id, obj["type"], title, obj, state)]
        if include_entities is not None and not all(item in include_entities for item in entity_ids):
            if is_bundle:
                docs[0].metadata["excluded_count"] += 1
            continue
        text = f"{title}\n{entity_id}\n{obj.get('description', '')}\n\n{_dump(obj)}"
        docs.append(Document(source_id=source, path=f"{path}#{obj['id']}" if is_bundle else path,
            revision=revision, url=url, title=title, content_type="application/stix+json", text=text,
            raw=_dump(obj).encode("utf-8") if is_bundle else raw, entities=entities, relations=relations,
            metadata=_metadata(entity_ids=entity_ids, platforms=obj.get("x_mitre_platforms", []),
                domains=["threat-intelligence"], entity_type=obj["type"], lifecycle_status=state, published_at=obj.get("created"),
                source_modified_at=obj.get("modified"), original_locator=locator,
                archive_path=path if is_bundle else None, raw_representation="normalized_object" if is_bundle else "original")))
    if not is_bundle and not docs:
        raise IngestionError(quarantine[0]["reason"] if quarantine else "No supported STIX object")
    return docs


class _SigmaLoader(yaml.SafeLoader):
    pass


def _yaml_mapping(loader: _SigmaLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    pairs = []
    for key, value in node.value:
        parsed_key = loader.construct_object(key, deep=deep)
        if not isinstance(parsed_key, (str, int, float, bool)):
            raise IngestionError("YAML mapping keys must be scalar")
        pairs.append((parsed_key, loader.construct_object(value, deep=deep)))
    return _unique_pairs(pairs)


_SigmaLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _yaml_mapping)


def _sigma(source: str, path: str, raw: bytes, revision: str, url: str) -> list[Document]:
    if len(raw) > MAX_YAML_BYTES:
        raise IngestionError("Sigma rule exceeds the YAML size limit")
    try:
        text = raw.decode("utf-8-sig")
        depth = 0
        for i, event in enumerate(yaml.parse(text)):
            if i > 100_000:
                raise IngestionError("YAML event limit exceeded")
            if isinstance(event, yaml.events.AliasEvent):
                raise IngestionError("YAML aliases are not accepted")
            if isinstance(event, (yaml.events.SequenceStartEvent, yaml.events.MappingStartEvent)):
                depth += 1
                if depth > 64:
                    raise IngestionError("YAML nesting limit exceeded")
            if isinstance(event, (yaml.events.SequenceEndEvent, yaml.events.MappingEndEvent)):
                depth -= 1
        data = yaml.load(text, Loader=_SigmaLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise IngestionError("Invalid, unsafe, or multi-document YAML") from exc
    if not isinstance(data, dict):
        raise IngestionError("Sigma must be a mapping")
    if any(key in data for key in ("correlation", "filter", "action")):
        raise UnsupportedFormat("Sigma correlations, filters and collections are not supported")
    if not isinstance(data.get("title"), str) or not isinstance(data.get("logsource"), dict) or not isinstance(data.get("detection"), dict):
        raise IngestionError("Sigma rule requires title, logsource and detection")
    if not isinstance(data["detection"].get("condition"), str):
        raise IngestionError("Sigma detection requires a condition")
    # Dates from SafeLoader are serialized explicitly; no Python tags can run.
    data = json.loads(_dump(data))
    rule_id = data.get("id")
    if rule_id is not None and (not isinstance(rule_id, str) or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", rule_id)):
        raise IngestionError("Invalid Sigma UUID")
    entity_id = f"sigma:{rule_id.lower()}" if rule_id else f"sigma-local:{source}/{path}"
    relations = []
    tags = data.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise IngestionError("Sigma tags must be an array of strings")
    for i, tag in enumerate(tags):
        if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag, flags=re.IGNORECASE):
            relations.append(_relation(entity_id, "mapped-to", f"attack:{tag.split('.', 1)[1].upper()}", f"/tags/{i}"))
        elif re.fullmatch(r"cve\.\d{4}\.\d{4,}", tag, flags=re.IGNORECASE):
            relations.append(_relation(entity_id, "references", "cve:" + tag.upper().replace(".", "-"), f"/tags/{i}"))
    state = str(data.get("status", "unspecified"))
    product = data["logsource"].get("product")
    return [Document(source_id=source, path=path, revision=revision, url=url, title=data["title"],
        content_type="application/yaml", text=text, raw=raw,
        entities=[_entity(entity_id, "sigma-rule", data["title"], data, state)], relations=relations,
        metadata=_metadata(entity_ids=[entity_id], platforms=[product] if product else [], domains=["detection"],
            entity_type="sigma-rule", lifecycle_status="deprecated" if state in {"deprecated", "unsupported"} else "current",
            source_status=state, published_at=data.get("date"), source_modified_at=data.get("modified"),
            logsource=data["logsource"], official_id=rule_id))]


def _cwe_relations(entity_id: str, container: dict, prefix: str) -> list[dict]:
    relations = []
    for i, problem in enumerate(container.get("problemTypes", [])):
        for j, description in enumerate(problem.get("descriptions", [])):
            cwe = description.get("cweId")
            if isinstance(cwe, str) and re.fullmatch(r"CWE-\d+", cwe):
                relations.append(_relation(entity_id, "associated-with-weakness", f"cwe:{cwe}", f"{prefix}/problemTypes/{i}/descriptions/{j}/cweId"))
    return relations


def _cvss_metric(value: Any, provider: str, locator: str) -> dict | None:
    if not isinstance(value, dict):
        return None
    score = value.get("baseScore")
    version = value.get("version")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
        return None
    if version not in {"2.0", "3.0", "3.1", "4.0"}:
        return None
    return {"version": version, "provider": provider, "base_score": score,
            "vector": value.get("vectorString"), "evidence_locator": locator}


def _container_cvss(container: dict, prefix: str) -> list[dict]:
    provider_metadata = container.get("providerMetadata", {})
    provider = provider_metadata.get("shortName") or provider_metadata.get("orgId") or "unspecified"
    result = []
    for i, metric in enumerate(container.get("metrics", [])):
        for key in ("cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0"):
            extracted = _cvss_metric(metric.get(key), provider, f"{prefix}/metrics/{i}/{key}")
            if extracted:
                extracted["provider_metadata"] = provider_metadata
                result.append(extracted)
    return result


def _cve(source: str, path: str, raw: bytes, revision: str, url: str) -> list[Document]:
    data = _json(raw)
    if data.get("dataType") != "CVE_RECORD" or data.get("dataVersion") not in CVE_SCHEMAS:
        raise UnsupportedFormat("Unsupported CVE dataType or dataVersion")
    metadata = data.get("cveMetadata", {})
    cve_id = metadata.get("cveId", "")
    state = metadata.get("state")
    if not isinstance(cve_id, str) or not CVE_ID.fullmatch(cve_id) or state not in {"PUBLISHED", "REJECTED"}:
        raise IngestionError("CVE requires a valid ID and PUBLISHED/REJECTED state")
    containers = data.get("containers", {})
    cna = containers.get("cna")
    if not isinstance(cna, dict):
        raise IngestionError("CVE record requires its CNA container")
    if not isinstance(containers.get("adp", []), list):
        raise IngestionError("CVE ADP containers must be an array")
    entity_id = f"cve:{cve_id}"
    title = cna.get("title", cve_id)
    relations = _cwe_relations(entity_id, cna, "/containers/cna")
    metrics = _container_cvss(cna, "/containers/cna")
    products = [item["product"] for item in cna.get("affected", []) if isinstance(item.get("product"), str)]
    for index, adp in enumerate(containers.get("adp", [])):
        relations.extend(_cwe_relations(entity_id, adp, f"/containers/adp/{index}"))
        metrics.extend(_container_cvss(adp, f"/containers/adp/{index}"))
    return [Document(source_id=source, path=path, revision=revision, url=url, title=f"{cve_id}: {title}",
        content_type="application/json", text=_dump(data), raw=raw,
        entities=[_entity(entity_id, "vulnerability", title, data, state)], relations=relations,
        metadata=_metadata(entity_ids=[entity_id], domains=["vulnerabilities"],
            lifecycle_status="rejected" if state == "REJECTED" else "current", source_status=state,
            entity_type="vulnerability", cvss_metrics=metrics, products=sorted(set(products)),
            schema_version=data["dataVersion"], published_at=metadata.get("datePublished"),
            source_modified_at=metadata.get("dateUpdated")))]


def _kev(source: str, path: str, raw: bytes, revision: str, url: str) -> list[Document]:
    data = _json(raw)
    rows = data.get("vulnerabilities")
    if not isinstance(rows, list) or data.get("count") != len(rows) or not data.get("catalogVersion") or not data.get("dateReleased"):
        raise IngestionError("KEV requires catalog metadata and a matching vulnerability count")
    docs = [_archive(source, path, revision, url, raw, catalog_version=data["catalogVersion"],
                     catalog_complete=True, catalog_date=data["dateReleased"], catalog_count=len(rows))]
    seen = set()
    for index, row in enumerate(rows):
        cve_id = row.get("cveID", "")
        if not CVE_ID.fullmatch(cve_id) or cve_id in seen:
            raise IngestionError("KEV contains an invalid or duplicate CVE ID")
        seen.add(cve_id)
        entity_id = f"cve:{cve_id}"
        title = row.get("vulnerabilityName", cve_id)
        attributes = {"kev_record": row, "catalog_version": data["catalogVersion"], "catalog_date": data["dateReleased"]}
        relations = [_relation(entity_id, "associated-with-weakness", f"cwe:{cwe}", f"/vulnerabilities/{index}/cwes/{i}")
                     for i, cwe in enumerate(row.get("cwes", [])) if isinstance(cwe, str) and re.fullmatch(r"CWE-\d+", cwe)]
        docs.append(Document(source_id=source, path=f"{path}#{cve_id}", revision=revision, url=url,
            title=f"{cve_id}: {title}", content_type="application/json", text=_dump(attributes),
            raw=_dump(row).encode("utf-8"), entities=[_entity(entity_id, "vulnerability", title, attributes, "listed-in-kev")],
            relations=relations, metadata=_metadata(entity_ids=[entity_id], domains=["vulnerabilities"],
                entity_type="vulnerability", kev_presence=True, products=[row["product"]] if isinstance(row.get("product"), str) else [],
                catalog_version=data["catalogVersion"], source_modified_at=data["dateReleased"],
                published_at=row.get("dateAdded"), original_locator=f"/vulnerabilities/{index}",
                archive_path=path, raw_representation="normalized_object")))
    return docs


def _nvd(source: str, path: str, raw: bytes, revision: str, url: str) -> list[Document]:
    data = _json(raw)
    if data.get("version") != "2.0" or not isinstance(data.get("vulnerabilities"), list):
        raise UnsupportedFormat("Only NVD API 2.0 envelopes are supported")
    docs = [_archive(source, path, revision, url, raw)]
    for index, item in enumerate(data["vulnerabilities"]):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not CVE_ID.fullmatch(cve_id):
            raise IngestionError("Invalid NVD CVE ID")
        entity_id = f"cve:{cve_id}"
        state = cve.get("vulnStatus", "unspecified")
        metrics = []
        for metric_type, items in cve.get("metrics", {}).items():
            for metric_index, item in enumerate(items):
                extracted = _cvss_metric(item.get("cvssData"), item.get("source", "unspecified"),
                                         f"/vulnerabilities/{index}/cve/metrics/{metric_type}/{metric_index}/cvssData")
                if extracted:
                    metrics.append(extracted)
        docs.append(Document(source_id=source, path=f"{path}#{cve_id}", revision=revision, url=url,
            title=f"NVD: {cve_id}", content_type="application/json", text=_dump(cve), raw=_dump(cve).encode("utf-8"),
            entities=[_entity(entity_id, "vulnerability", cve_id, {"nvd_record": cve}, state)],
            metadata=_metadata(entity_ids=[entity_id], domains=["vulnerabilities"],
                lifecycle_status="rejected" if state.lower() == "rejected" else "current", source_status=state,
                entity_type="vulnerability", cvss_metrics=metrics, products=[],
                published_at=cve.get("published"), source_modified_at=cve.get("lastModified"),
                original_locator=f"/vulnerabilities/{index}/cve", archive_path=path, raw_representation="normalized_object")))
    return docs


def parse_source(source_id: str, path: str, raw: bytes, revision: str, url: str,
                 *, include_entities: list[str] | None = None) -> list[Document]:
    """Parse a source file without fetching references or evaluating source content."""
    if len(raw) > MAX_FILE_BYTES:
        raise IngestionError("Source file exceeds size limit")
    kind = SOURCE_ALIASES.get(source_id)
    if kind is None:
        raise UnsupportedFormat(f"Unknown source: {source_id}")
    if Path(path).suffix.lower() in {".md", ".markdown"}:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeError as exc:
            raise IngestionError("Markdown must be UTF-8") from exc
        if "\x00" in text:
            raise IngestionError("Markdown contains NUL characters")
        title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        return [Document(source_id=source_id, path=path, revision=revision, url=url,
            title=title_match.group(1).strip() if title_match else Path(path).stem,
            content_type="text/markdown", text=text, raw=raw,
            metadata=_metadata(domains=["application-security"] if kind == "owasp" else ["reference"],
                record_kind="documentation"))]
    adapter = {"attack": _attack, "sigma": _sigma, "cve": _cve, "kev": _kev, "nvd": _nvd}.get(kind)
    if adapter is None:
        raise UnsupportedFormat("OWASP adapter supports Markdown only")
    try:
        if kind == "attack":
            return _attack(source_id, path, raw, revision, url, include_entities=include_entities)
        return adapter(source_id, path, raw, revision, url)
    except (TypeError, AttributeError, KeyError, IndexError, RecursionError) as exc:
        raise IngestionError("Invalid source structure") from exc


def _inside(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise IngestionError("Manifest path escapes its source directory")
    return resolved


def load_manifest(path: Path) -> tuple[list[Document], dict]:
    """Load an explicitly selected local snapshot and report quarantined files.

    Roots and files must stay below the manifest directory. A manifest may narrow
    a bundle using include_entities; archives remain preserved. Failures become
    source.quarantine entries, enabling the publisher to reject partial updates.
    """
    path = Path(path).resolve()
    if path.stat().st_size > 2 * 1024 * 1024:
        raise IngestionError("Manifest too large")
    manifest = _json(path.read_bytes())
    entries = manifest.get("sources")
    if not isinstance(entries, list) or not entries or len(entries) > 100:
        raise IngestionError("Manifest requires 1 to 100 sources")
    documents: list[Document] = []
    sources: dict = {}
    for config in entries:
        if not isinstance(config, dict):
            raise IngestionError("Each source must be an object")
        source_id = config.get("source_id")
        if source_id not in SOURCE_ALIASES or source_id in sources:
            raise IngestionError("Unknown or duplicate source_id in manifest")
        if not isinstance(config.get("revision"), str) or not config["revision"]:
            raise IngestionError("Every source requires an explicit revision")
        base_url = config.get("base_url")
        if not isinstance(base_url, str):
            raise IngestionError("Every source requires its base_url")
        try:
            origin = urlsplit(base_url)
        except ValueError as exc:
            raise IngestionError("Invalid source base_url") from exc
        if origin.scheme != "https" or not origin.hostname or origin.username or origin.password:
            raise IngestionError("Source base_url must be HTTPS without credentials")
        for field in ("file_hashes", "file_urls"):
            mapping = config.get(field, {})
            if not isinstance(mapping, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()):
                raise IngestionError(f"{field} must be a mapping")
        if not isinstance(config.get("notice_files", []), list) or not all(isinstance(item, str) for item in config.get("notice_files", [])):
            raise IngestionError("notice_files must be an array")
        root_name = config.get("root")
        if not isinstance(root_name, str) or Path(root_name).is_absolute():
            raise IngestionError("Source root must be relative to the manifest")
        root = _inside(path.parent / root_name, path.parent)
        if not root.is_dir():
            raise IngestionError("Source root does not exist")
        stats = {**config, "parser_version": PARSER_VERSION, "documents": 0, "files": 0, "quarantine": [], "excluded": [], "excluded_count": 0,
                 "catalog_complete": False}
        sources[source_id] = stats
        files = config.get("files")
        if files is None:
            files = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
        if not isinstance(files, list) or not files or len(files) > MAX_FILES or not all(isinstance(f, str) for f in files):
            raise IngestionError("Source files must be a nonempty bounded list")
        if len(files) != len(set(files)):
            raise IngestionError("Duplicate file in source manifest")
        included = config.get("include_entities")
        if included is not None and (not isinstance(included, list) or not all(isinstance(e, str) for e in included)):
            raise IngestionError("include_entities must be an array of IDs")
        notices = set(config.get("notice_files", []))
        for relative in sorted(files):
            file_path = _inside(root / relative, root)
            if Path(relative).is_absolute():
                raise IngestionError("Source file must be relative")
            try:
                if file_path.stat().st_size > MAX_FILE_BYTES:
                    raise IngestionError("Source file exceeds size limit")
                raw = file_path.read_bytes()
                file_hash = hashlib.sha256(raw).hexdigest()
                expected_hash = config.get("file_hashes", {}).get(relative)
                if expected_hash and file_hash != expected_hash:
                    raise IngestionError("Source checksum does not match manifest")
                url = config.get("file_urls", {}).get(relative) or config.get("base_url", "").rstrip("/") + "/" + quote(relative, safe="/")
                try:
                    parsed_url = urlsplit(url)
                except ValueError as exc:
                    raise IngestionError("Invalid document source URL") from exc
                if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password:
                    raise IngestionError("Document source URL must be HTTPS without credentials")
                if relative in notices:
                    parsed = [_archive(source_id, relative, config["revision"], url, raw, record_purpose="license_notice")]
                else:
                    parsed = parse_source(source_id, relative, raw, config["revision"], url, include_entities=included)
                stats["files"] += 1
                for doc in parsed:
                    if doc.metadata.get("catalog_complete") and included is None:
                        stats.update({key: doc.metadata[key] for key in ("catalog_complete", "catalog_version", "catalog_date", "catalog_count")})
                    stats["excluded_count"] += doc.metadata.get("excluded_count", 0)
                    for item in doc.metadata.get("quarantine", []):
                        stats["quarantine"].append({"path": relative, **item})
                    if included is not None and doc.metadata.get("record_kind") not in {"source_archive", "documentation"}:
                        ids = doc.metadata.get("entity_ids", [])
                        keep = bool(ids) and all(entity_id in included for entity_id in ids)
                        if not keep:
                            stats["excluded"].append({"path": doc.path, "reason": "outside pilot selection"})
                            continue
                    doc.metadata.update({"checked_at": config.get("checked_at"), "license_reference": config.get("license_reference"),
                                         "selection_policy": config.get("selection_policy"), "source_file_sha256": file_hash})
                    documents.append(doc)
                    stats["documents"] += 1
            except IngestionError as exc:
                stats["quarantine"].append({"path": relative, "reason": str(exc)})
            except OSError as exc:
                stats["quarantine"].append({"path": relative, "reason": f"Source file unavailable ({type(exc).__name__})"})
        stats["status"] = "quarantined" if stats["quarantine"] else "parsed"
        if stats["quarantine"]:
            stats["catalog_complete"] = False
        stats["excluded_count"] += len(stats["excluded"])
    return documents, sources
