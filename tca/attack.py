"""Load MITRE ATT&CK (v18+ STIX) and resolve technique -> detection strategy -> analytic -> log sources."""
import json
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


@dataclass(frozen=True)
class LogRef:
    source: str          # e.g. "WinEventLog:Security"
    channel: str         # e.g. "EventCode=4662" or free text
    component: str       # data component name, e.g. "Active Directory Object Access"

    def event_codes(self):
        m = re.match(r"\s*EventCode\s*=\s*(.+)", self.channel, re.I)
        return {c.strip() for c in m.group(1).split(",")} if m else set()


@dataclass
class Analytic:
    name: str
    platforms: list
    refs: list = field(default_factory=list)


@dataclass
class Technique:
    id: str
    name: str
    tactics: list
    platforms: list
    analytics: list = field(default_factory=list)


def fetch(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(STIX_URL, path)
    return path


def _ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def load(path) -> dict:
    """Return {technique_id: Technique} for current (not revoked or deprecated) techniques."""
    objs = json.loads(Path(path).read_text(encoding="utf-8"))["objects"]
    live = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in live}
    comps = {o["id"]: o["name"] for o in live if o["type"] == "x-mitre-data-component"}

    analytics = {}
    for o in live:
        if o["type"] == "x-mitre-analytic":
            refs = [LogRef(r.get("name", ""), r.get("channel", ""), comps.get(r.get("x_mitre_data_component_ref"), ""))
                    for r in o.get("x_mitre_log_source_references", [])]
            analytics[o["id"]] = Analytic(o.get("name", ""), o.get("x_mitre_platforms", []), refs)

    techniques = {}
    for o in live:
        if o["type"] == "attack-pattern":
            tid = _ext_id(o)
            if tid:
                tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
                techniques[o["id"]] = Technique(tid, o["name"], tactics, o.get("x_mitre_platforms", []))

    for o in live:
        if o["type"] == "relationship" and o["relationship_type"] == "detects":
            strat, tech = by_id.get(o["source_ref"]), techniques.get(o["target_ref"])
            if strat and tech and strat["type"] == "x-mitre-detection-strategy":
                tech.analytics += [analytics[a] for a in strat.get("x_mitre_analytic_refs", []) if a in analytics]

    return {t.id: t for t in techniques.values()}


def group_techniques(path, group_name: str) -> set:
    """Technique IDs used by an ATT&CK group (intrusion-set), matched on name or alias."""
    objs = json.loads(Path(path).read_text(encoding="utf-8"))["objects"]
    want = group_name.lower()
    groups = [o for o in objs if o["type"] == "intrusion-set"
              and (o["name"].lower() == want or want in [a.lower() for a in o.get("aliases", [])])]
    if not groups:
        raise SystemExit(f"group not found: {group_name}")
    gid = groups[0]["id"]
    tech = {o["id"]: _ext_id(o) for o in objs if o["type"] == "attack-pattern"}
    return {tech[r["target_ref"]] for r in objs if r["type"] == "relationship" and r["relationship_type"] == "uses"
            and r["source_ref"] == gid and r["target_ref"] in tech and tech[r["target_ref"]]}
