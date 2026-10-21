"""Explicitly reviewed public-source connectors. No caller-controlled hosts."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    title: str
    repository: str
    branch: str
    paths: tuple[str, ...]
    subjects: tuple[str, ...]
    format: str = "text"
    discovery: str = "fixed"
    prefixes: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = (".md",)
    license_path: str = "LICENSE"
    ttl_seconds: int = 86400
    max_bytes: int = 4 * 1024 * 1024
    sample_query: str = ""
    sample_path: str | None = None
    expected_text: str = ""
    access_note: str = "Public source; source license remains applicable."
    urls: tuple[tuple[str, str], ...] = ()
    homepage: str = ""
    license_url: str = ""
    latest_only: bool = False
    id_kind: str = ""
    url_template: str = ""
    min_interval_seconds: float = 0.0
    request_budget_seconds: int = 30


SOURCES = {
    "attack": SourceSpec(
        "attack", "MITRE ATT&CK Enterprise", "mitre-attack/attack-stix-data", "master",
        ("enterprise-attack/enterprise-attack.json",),
        ("attack", "technique", "tactic", "powershell", "técnica", "mitre"),
        format="stix", license_path="LICENSE.txt", max_bytes=80 * 1024 * 1024,
        sample_query="T1059.001 PowerShell", expected_text="PowerShell",
    ),
    "sigma": SourceSpec(
        "sigma", "SigmaHQ detection rules", "SigmaHQ/sigma", "master", (),
        ("sigma", "detection", "siem", "powershell", "detecção", "logs"),
        discovery="tree", prefixes=("rules/", "rules-emerging-threats/", "rules-threat-hunting/"),
        suffixes=(".yml", ".yaml"), sample_query="powershell encoded", expected_text="PowerShell",
    ),
    "cve": SourceSpec(
        "cve", "CVE List V5", "CVEProject/cvelistV5", "main", (),
        ("cve", "vulnerability", "vulnerabilidade", "affected", "cna"),
        discovery="cve", format="cve", license_path="README.md", ttl_seconds=3600,
        license_url="https://www.cve.org/Legal/TermsOfUse",
        sample_query="CVE-2021-44228", expected_text="CVE-2021-44228",
        access_note="CVE Program Terms of Use; remote lookup requires an exact CVE identifier.",
    ),
    "kev": SourceSpec(
        "kev", "CISA Known Exploited Vulnerabilities", "cisagov/kev-data", "develop",
        ("known_exploited_vulnerabilities.json",),
        ("kev", "cisa", "exploited", "explorada", "ransomware", "prazo"),
        format="kev", ttl_seconds=3600, sample_query="CVE-2021-44228", expected_text="CVE-2021-44228",
    ),
    "attack-mobile": SourceSpec(
        "attack-mobile", "MITRE ATT&CK Mobile", "mitre-attack/attack-stix-data", "master",
        ("mobile-attack/mobile-attack.json",), ("mobile", "android", "ios", "attack"),
        format="stix", license_path="LICENSE.txt", max_bytes=30 * 1024 * 1024,
        sample_query="T1407", expected_text="T1407",
    ),
    "attack-ics": SourceSpec(
        "attack-ics", "MITRE ATT&CK ICS", "mitre-attack/attack-stix-data", "master",
        ("ics-attack/ics-attack.json",), ("ics", "industrial", "scada", "plc", "attack"),
        format="stix", license_path="LICENSE.txt", max_bytes=30 * 1024 * 1024,
        sample_query="T0800", expected_text="T0800",
    ),
    "d3fend": SourceSpec(
        "d3fend", "MITRE D3FEND", "", "", ("d3fend.json",),
        ("d3fend", "defense", "defesa", "countermeasure", "contramedida"),
        discovery="public", format="json", max_bytes=32 * 1024 * 1024,
        urls=(("d3fend.json", "https://d3fend.mitre.org/ontologies/d3fend.json"),),
        homepage="https://d3fend.mitre.org/resources/ontology/", license_url="https://d3fend.mitre.org/tou/",
        sample_query="Network Traffic Filtering", expected_text="Filtering",
    ),
    "atlas": SourceSpec(
        "atlas", "MITRE ATLAS", "mitre-atlas/atlas-data", "main", (),
        ("atlas", "ai", "ia", "llm", "model", "adversarial", "prompt"),
        discovery="tree", prefixes=("dist/v6/",), suffixes=(".yaml",), latest_only=True,
        format="atlas", max_bytes=16 * 1024 * 1024, sample_query="prompt injection", expected_text="prompt",
    ),
    "capec": SourceSpec(
        "capec", "MITRE CAPEC", "mitre/cti", "master", ("capec/2.1/stix-capec.json",),
        ("capec", "attack pattern", "padrão ataque", "weakness"), format="stix", license_path="LICENSE.txt",
        max_bytes=32 * 1024 * 1024, sample_query="CAPEC-66", expected_text="CAPEC-66",
    ),
    "hacktricks": SourceSpec(
        "hacktricks", "HackTricks", "HackTricks-wiki/hacktricks", "master", (),
        ("hacktricks", "pentest", "enumeration", "linux", "web", "enumeração"),
        discovery="tree", prefixes=("src/",), license_path="src/LICENSE.md",
        sample_query="sql injection", expected_text="injection",
        access_note="CC BY-NC 4.0, with separate conditions for third-party content; consult upstream for commercial use. Local cache only.",
    ),
    "payloads": SourceSpec(
        "payloads", "PayloadsAllTheThings", "swisskyrepo/PayloadsAllTheThings", "master", (),
        ("payload", "pentest", "injection", "web", "red team"),
        discovery="tree", prefixes=("",), sample_query="sql injection", expected_text="injection",
        access_note="Text reference only; examples are never executed.",
    ),
    "internal-all-the-things": SourceSpec(
        "internal-all-the-things", "InternalAllTheThings", "swisskyrepo/InternalAllTheThings", "main", (),
        ("internal", "active directory", "kerberos", "windows", "red team"),
        discovery="tree", prefixes=("docs/",), sample_query="kerberos", expected_text="Kerberos",
        license_path="README.md",
        access_note="General redistribution license not confirmed upstream. Text reference only; examples are never executed.",
    ),
    "gtfobins": SourceSpec(
        "gtfobins", "GTFOBins", "GTFOBins/GTFOBins.github.io", "master", (),
        ("gtfobins", "unix", "linux", "sudo", "suid", "binários"),
        discovery="tree", prefixes=("_gtfobins/",), suffixes=("",), sample_query="find", expected_text="find",
    ),
    "lolbas": SourceSpec(
        "lolbas", "LOLBAS", "LOLBAS-Project/LOLBAS", "master", (),
        ("lolbas", "windows", "lolbin", "certutil", "rundll32"),
        discovery="tree", prefixes=("yml/",), suffixes=(".yml", ".yaml"),
        sample_query="certutil", expected_text="Certutil",
    ),
    "wadcoms": SourceSpec(
        "wadcoms", "WADComs", "WADComs/WADComs.github.io", "master", (),
        ("wadcoms", "active directory", "windows", "impacket"),
        discovery="tree", prefixes=("_wadcoms/",), suffixes=("",),
        sample_query="kerbrute", expected_text="kerbrute",
    ),
    "loobins": SourceSpec(
        "loobins", "LOOBins", "infosecB/LOOBins", "main", (),
        ("loobins", "macos", "mac", "apple", "osascript"),
        discovery="tree", prefixes=("LOOBins/",), suffixes=(".yml", ".yaml"),
        sample_query="osascript", expected_text="osascript",
    ),
    "owasp-top10": SourceSpec(
        "owasp-top10", "OWASP Top 10 Web 2025", "OWASP/Top10", "master", (),
        ("owasp", "top10", "web", "risks", "riscos", "access control"),
        discovery="tree", prefixes=("2025/docs/en/",), license_path="LICENSE",
        sample_query="broken access control", expected_text="access control",
    ),
    "owasp-api": SourceSpec(
        "owasp-api", "OWASP API Security Top 10 2023", "OWASP/API-Security", "master", (),
        ("owasp", "api", "bola", "idor", "authorization", "autorização"),
        discovery="tree", prefixes=("editions/2023/en/",), license_path="LICENSE",
        sample_query="broken object level authorization", expected_text="authorization",
    ),
    "owasp-mobile": SourceSpec(
        "owasp-mobile", "OWASP Mobile Top 10 2024", "OWASP/www-project-mobile-top-10", "master", (),
        ("owasp", "mobile", "android", "ios", "credential", "credenciais"),
        discovery="tree", prefixes=("2023-risks/",), license_url="https://owasp.org/projects/mobile-top-10",
        sample_query="improper credential usage", expected_text="credential",
        access_note="2024 final release is stored upstream under 2023-risks; legacy editions excluded. Project-specific redistribution license not confirmed; consult the official project.",
    ),
    "owasp-llm": SourceSpec(
        "owasp-llm", "OWASP Top 10 for LLM Applications 2025", "OWASP/www-project-top-10-for-large-language-model-applications", "main", (),
        ("owasp", "llm", "prompt", "ai", "ia", "rag", "embedding"),
        discovery="tree", prefixes=("2_0_vulns/LLM",), license_path="LICENSE.md",
        sample_query="prompt injection", expected_text="Prompt Injection",
    ),
    "owasp-wstg": SourceSpec(
        "owasp-wstg", "OWASP Web Security Testing Guide (development branch)", "OWASP/wstg", "master", (),
        ("owasp", "wstg", "testing", "testes", "web", "authentication"),
        discovery="tree", prefixes=("document/",), license_path="LICENSE",
        sample_query="sql injection", expected_text="SQL Injection",
        access_note="Current upstream development branch, pinned by commit; not a frozen published release.",
    ),
    "yara": SourceSpec(
        "yara", "YARA-Rules", "Yara-Rules/rules", "master", (),
        ("yara", "malware", "signature", "assinatura", "ransomware"),
        discovery="tree", prefixes=("malware/", "packers/", "crypto/", "email/", "webshells/"),
        suffixes=(".yar", ".yara"), sample_query="wannacry", expected_text="WannaCry",
        access_note="Rule source text only; rules are neither compiled nor executed.",
    ),
    "atomic-red-team": SourceSpec(
        "atomic-red-team", "Atomic Red Team", "redcanaryco/atomic-red-team", "master", (),
        ("atomic", "red team", "detection testing", "detecção", "validation", "validação"),
        discovery="tree", prefixes=("atomics/",), suffixes=(".yaml",), license_path="LICENSE.txt",
        sample_query="T1059.001", expected_text="T1059.001",
        access_note="Test definitions as evidence; no tests, dependencies or payloads are executed/downloaded.",
    ),
    "windows-events": SourceSpec(
        "windows-events", "Microsoft Windows Security Auditing events", "", "", (),
        ("event", "evento", "windows", "eventid", "auditing", "auditoria", "logon"),
        discovery="http-id", format="html", id_kind="event",
        url_template="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{id}",
        homepage="https://learn.microsoft.com/en-us/windows/security/", license_url="https://learn.microsoft.com/en-us/legal/termsofuse",
        sample_query="event 4624", expected_text="4624",
        access_note="Official Microsoft alternative to the unverified EventKB name. Previous-versions Windows 10 auditing documentation; request an exact 4-digit Event ID.",
    ),
    "nvd": SourceSpec(
        "nvd", "NIST National Vulnerability Database", "", "", (),
        ("nvd", "nist", "cve", "cvss", "cpe", "vulnerability", "vulnerabilidade"),
        discovery="http-id", format="nvd", id_kind="cve", ttl_seconds=3600, min_interval_seconds=6.0,
        url_template="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}",
        homepage="https://nvd.nist.gov/developers/vulnerabilities", license_url="https://www.nist.gov/open/license",
        sample_query="CVE-2021-44228", expected_text="CVE-2021-44228",
        access_note="Exact CVE lookup, API 2.0 without key. Response timestamp is excluded from record revision; original bytes retained.",
    ),
    "cwe": SourceSpec(
        "cwe", "MITRE Common Weakness Enumeration", "", "", (),
        ("cwe", "weakness", "fraqueza", "code", "código", "xss"),
        discovery="http-id", format="cwe", id_kind="cwe",
        url_template="https://cwe-api.mitre.org/api/v1/cwe/weakness/{id}",
        homepage="https://cwe.mitre.org/data/downloads.html", license_url="https://cwe.mitre.org/about/termsofuse.html",
        sample_query="CWE-79", expected_text="CWE-79",
        access_note="Exact weakness ID lookup using the official public MITRE API.",
    ),
    "exploit-db": SourceSpec(
        "exploit-db", "Exploit Database", "exploit-database/exploitdb", "main", (),
        ("exploit-db", "exploitdb", "edb", "exploit", "vulnerability", "vulnerabilidade"),
        discovery="gitlab-exploit-csv", prefixes=("exploits/",), license_path="LICENSE.md",
        homepage="https://gitlab.com/exploit-database/exploitdb",
        sample_query="EDB-45233", expected_text="EDB-45233",
        access_note="Official GitLab CSV discovery by canonical EDB-ID (EDB-45233), CVE or description. Only selected textual source files are cached; shellcode catalog and binary files excluded. Nothing is executed; upstream and individual source licenses apply.",
    ),
    "malapi": SourceSpec(
        "malapi", "MalAPI", "", "", (),
        ("malapi", "winapi", "malware api", "virtualalloc", "createremotethread"),
        discovery="http-id", format="html", id_kind="malapi", max_bytes=2 * 1024 * 1024,
        url_template="https://malapi.io/winapi/{id}",
        homepage="https://malapi.io/", license_url="https://malapi.io/",
        sample_query="VirtualAlloc", expected_text="VirtualAlloc",
        access_note="Connector prepared for exact API names (VirtualAlloc or path VirtualAlloc.html). Official origin had a DNS failure on 2026-10-21; no live-verified MalAPI content is available from that check. No substitute is attributed to MalAPI. Consult live cache status; upstream content terms remain applicable when the service returns.",
    ),
    "unprotect": SourceSpec(
        "unprotect", "Unprotect Project contribution descriptions", "Unprotect-Project/ContributeV2", "main", (),
        ("unprotect", "evasion", "evasão", "anti-debug", "malware", "obfuscation", "ofuscação"),
        discovery="tree", prefixes=("Techniques/",), suffixes=("/description.txt",),
        license_url="https://unprotect.it/page/terms-and-conditions/",
        sample_query="API Obfuscation", sample_path="Techniques/API Obfuscation/description.txt", expected_text="API",
        access_note="Primary technique descriptions one directory below Techniques/ in the official contribution repository only; not complete coverage of the website. Snippet descriptions, code, rules, binary files and auxiliary metadata are excluded. No general open license was confirmed; consult project terms and individual content permissions before redistribution.",
    ),
    "capa": SourceSpec(
        "capa", "Mandiant CAPA Rules", "mandiant/capa-rules", "master", (),
        ("capa", "malware", "capability", "capacidade", "debugger", "reverse engineering", "engenharia reversa"),
        discovery="tree", suffixes=(".yml",), license_path="LICENSE.txt",
        prefixes=(
            "anti-analysis/", "collection/", "communication/", "compiler/", "data-manipulation/",
            "executable/", "exploitation/", "host-interaction/", "impact/", "internal/", "lib/",
            "linking/", "load-code/", "malware-family/", "nursery/", "persistence/", "runtime/", "targeting/",
        ),
        sample_query="check for debugger via API",
        sample_path="anti-analysis/anti-debugging/debugger-detection/check-for-debugger-via-api.yml",
        expected_text="CheckRemoteDebuggerPresent",
        access_note="Textual capability rules from reviewed rule directories, including experimental nursery rules identified by their path. Workflow/configuration YAML, documentation and binaries are excluded. Rules are neither compiled nor executed; consult their metadata and context before relying on a detection.",
    ),
    "vx-papers": SourceSpec(
        "vx-papers", "VX-Underground selected papers", "vxunderground/VXUG-Papers", "main",
        (
            "Abusing the Windows Power Management API/AbusingtheWindowsPowerManagementAPI.pdf",
            "An Alternative Method To Enumerate Processes.pdf",
            "From a C project through assembly to shellcode.pdf",
            "Hells Gate/HellsGate.pdf",
            "Identifying Antivirus Software by enumerating Minifilter String Names/IdentifyingAntivirusSoftwarebyenumeratingMinifilterStringNames.pdf",
            "Infecting Android Applications The New Way/InfectingAndroidApplicationsTheNewWay.pdf",
            "The Fake Entry Point Trick.txt",
            "The Persistence Series/Commandeering Context Menu Entries/CommandeeringContextMenuEntries.pdf",
            "The Persistence Series/Cryogenically Frozen Malware/Cryogenically Frozen Malware.pdf",
            "The Persistence Series/Kusarigama/Kusarigama.pdf",
            "The Persistence Series/Masquerading the HKCU Run Key/MasqueradingtheHKCURunKey.pdf",
            "The Persistence Series/Persistence via Recycle Bin/Persistence_via_Recycle_Bin.pdf",
            "USB Propagation/USB Propagation.pdf",
            "Weaponizing Windows Virtualization/WeaponizingWindowsVirtualization.pdf",
            "Wormable SSH/Wormable SSH.pdf",
        ),
        ("vx", "vx-underground", "papers", "malware", "reverse engineering", "engenharia reversa"),
        discovery="tree", format="paper", max_bytes=16 * 1024 * 1024,
        license_url="https://github.com/vxunderground/VXUG-Papers",
        sample_query="enumerate processes", sample_path="An Alternative Method To Enumerate Processes.pdf",
        expected_text="process",
        access_note="Restricted list of 14 research PDFs and one text article; implementations, binaries and other repository content are excluded. Only text is extracted: no OCR, active content, attachment extraction or code execution. PDF layout and reading order can be lost; the original remains available. Copyright and permissions vary by paper; no general redistribution license was confirmed. Cache locally, do not publish a corpus.",
    ),
    "nist-csf": SourceSpec(
        "nist-csf", "NIST Cybersecurity Framework 2.0 (OSCAL)", "usnistgov/oscal-content", "main",
        ("nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json",),
        ("nist csf", "csf", "framework", "governance", "governança", "grc", "risk", "risco"),
        format="json", max_bytes=16 * 1024 * 1024, license_path="LICENSE.md",
        sample_query="GV.OC", expected_text="GV.OC",
        access_note="Official electronic OSCAL catalog of CSF 2.0, pinned to a repository commit. The OSCAL catalog version can differ from the framework edition. Source text supports research and does not establish an organization's compliance.",
    ),
    "nist-800-53": SourceSpec(
        "nist-800-53", "NIST SP 800-53 Rev. 5 controls and assessment procedures (OSCAL)", "usnistgov/oscal-content", "main",
        ("nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",),
        ("nist", "800-53", "80053", "oscal", "control", "controle", "assessment", "avaliação", "grc"),
        format="json", max_bytes=16 * 1024 * 1024, license_path="LICENSE.md",
        sample_query="Account Management", expected_text="Account Management",
        access_note="Official OSCAL Rev. 5 catalog, including controls and SP 800-53A assessment procedures as identified in upstream metadata. Pinned commit and original metadata identify the exact release; catalog updates do not establish an organization's compliance.",
    ),
    "cis-controls": SourceSpec(
        "cis-controls", "CIS Controls v8 Assessment Specification", "", "", (),
        ("cis", "control", "controle", "inventory", "inventário", "grc"),
        discovery="http-id", format="html", id_kind="cis-control",
        url_template="https://cas.docs.cisecurity.org/en/latest/source/Controls{id}/",
        homepage="https://cas.docs.cisecurity.org/en/latest/",
        license_url="https://cas.docs.cisecurity.org/en/latest/source/terms-of-use/",
        sample_query="Control 1 inventory", expected_text="Inventory",
        access_note="Public Controls Assessment Specification v8; select Control 1 through Control 18. CC BY-NC-ND 4.0 terms apply to the source; commercial use requires permission. Local evidence extraction is labelled derived; this connector does not redistribute the corpus or certify compliance.",
    ),
    "lgpd": SourceSpec(
        "lgpd", "LGPD — texto atualizado da Câmara dos Deputados", "", "", ("lgpd-atualizada.html",),
        ("lgpd", "privacidade", "privacy", "dados pessoais", "lei", "brasil", "grc"),
        discovery="public", format="lgpd",
        urls=(("lgpd-atualizada.html", "https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-normaatualizada-pl.html"),),
        homepage="https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-norma-pl.html",
        license_url="https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-norma-pl.html",
        sample_query="LGPD princípios dados pessoais", expected_text="dados pessoais",
        access_note="Official updated legislative text maintained by the Brazilian Chamber of Deputies. This named official source replaces the currently unavailable Planalto endpoint. Retrieval date and byte hash identify the consulted text; extraction is not a legal interpretation or a guarantee of all later amendments.",
    ),
    "gdpr": SourceSpec(
        "gdpr", "GDPR — official English original and consolidated text", "", "",
        ("gdpr-original-en.html", "gdpr-consolidated-en.html"),
        ("gdpr", "rgpd", "privacy", "privacidade", "data protection", "proteção dados", "grc"),
        discovery="public", format="gdpr",
        urls=(
            ("gdpr-original-en.html", "https://publications.europa.eu/resource/cellar/3e485e15-11bd-11e6-ba9a-01aa75ed71a1.0006.03/DOC_1"),
            ("gdpr-consolidated-en.html", "https://publications.europa.eu/resource/cellar/5f2552c2-cc45-11e6-ad7c-01aa75ed71a1.0022.03/DOC_1"),
        ),
        homepage="https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng",
        license_url="https://eur-lex.europa.eu/content/legal-notice/legal-notice.html?locale=en",
        sample_query="Article 5 personal data", sample_path="gdpr-consolidated-en.html", expected_text="personal data",
        access_note="English publications from the documented public EU Cellar service: original 2016 regulation and separately identified consolidated text dated 04.05.2016 with 2018 corrigendum. Rechecking these fixed publications does not discover later legal amendments. Consolidated text reuse requires attribution; retain the EU legal notice. No legal/compliance conclusion is inferred.",
    ),
    "iso27001": SourceSpec(
        "iso27001", "ISO/IEC 27001 — official open metadata only", "", "", ("iso_deliverables_metadata.csv",),
        ("iso", "27001", "isms", "sgsi", "standard", "norma", "grc"),
        discovery="public", format="iso-metadata", max_bytes=96 * 1024 * 1024, request_budget_seconds=90,
        urls=(("iso_deliverables_metadata.csv", "https://isopublicstorageprod.blob.core.windows.net/opendata/_latest/iso_deliverables_metadata/csv/iso_deliverables_metadata.csv"),),
        homepage="https://www.iso.org/open-data.html#iso_deliverables_metadata",
        license_url="https://opendatacommons.org/licenses/by/1-0/",
        sample_query="ISO 27001", expected_text="27001",
        access_note="ODC-By 1.0 official ISO Open Data metadata, with attribution. The full CSV dataset is retained locally for integrity; searchable projection selects ISO/IEC 27001 editions and supplements. Normative text is not included: ISO 27001 is not a freely redistributable standard. Recheck stage, edition and replacement fields before citing metadata.",
    ),
}
