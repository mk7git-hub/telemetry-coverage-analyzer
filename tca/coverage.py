"""Score coverage of a threat model against a log-source inventory, and value each source."""
from collections import defaultdict
from dataclasses import dataclass

import yaml

FULL, PARTIAL, NONE, NO_GUIDANCE = "full", "partial", "none", "no-guidance"


@dataclass
class Source:
    name: str
    channels: object         # "*" or list of event codes / channel strings
    daily_gb: float = 0.0
    cost_per_gb: float = 0.0
    normalized: bool = False
    platforms: tuple = ()

    @property
    def monthly_cost(self):
        return round(self.daily_gb * self.cost_per_gb * 30, 2)

    def provides(self, ref) -> bool:
        if ref.source.lower() != self.name.lower():
            return False
        if self.channels == "*":
            return True
        codes = ref.event_codes()
        have = {str(c).strip().lower() for c in self.channels}
        if codes:
            return bool(codes & have)          # any listed event code is enough for that signal
        return ref.channel.strip().lower() in have


def load_inventory(path):
    data = yaml.safe_load(open(path, encoding="utf-8"))
    sources = [Source(s["name"], s.get("channels", "*"), float(s.get("daily_gb", 0)), float(s.get("cost_per_gb", 0)),
                      bool(s.get("normalized", False)), tuple(s.get("platforms", ()))) for s in data["sources"]]
    return data.get("platforms", []), sources


def analytic_status(analytic, sources):
    if not analytic.refs:
        return NONE, []
    hits = [any(s.provides(r) for s in sources) for r in analytic.refs]
    if all(hits):
        return FULL, analytic.refs
    if any(hits):
        return PARTIAL, [r for r, h in zip(analytic.refs, hits) if not h]
    return NONE, analytic.refs


def score(techniques: dict, threat_model: set, platforms: list, sources: list):
    """Return per-technique results: status, missing log refs, and which sources make it work."""
    results = {}
    rank = {FULL: 3, PARTIAL: 2, NONE: 1, NO_GUIDANCE: 0}
    for tid in sorted(threat_model):
        t = techniques.get(tid)
        if not t:
            results[tid] = {"name": "(not in this ATT&CK version)", "tactics": [], "status": NO_GUIDANCE, "missing": [], "enablers": set()}
            continue
        analytics = [a for a in t.analytics if not platforms or set(a.platforms) & set(platforms)]
        if not analytics:
            results[tid] = {"name": t.name, "tactics": t.tactics, "status": NO_GUIDANCE, "missing": [], "enablers": set()}
            continue
        scored = [(a, *analytic_status(a, sources)) for a in analytics]
        a_best, best, missing = max(scored, key=lambda x: (rank[x[1]], -len(x[2])))
        enablers = {s.name for a, st, _ in scored if st == FULL for r in a.refs for s in sources if s.provides(r)}
        results[tid] = {"name": t.name, "tactics": t.tactics, "status": best, "missing": missing or [], "enablers": enablers}
    return results


def source_value(results, sources):
    """Techniques each source helps cover, techniques only it covers, and cost per covered technique."""
    helps, only = defaultdict(set), defaultdict(set)
    for tid, r in results.items():
        if r["status"] == FULL:
            for s in r["enablers"]:
                helps[s].add(tid)
            if len(r["enablers"]) == 1:
                only[next(iter(r["enablers"]))].add(tid)
    rows = []
    for s in sources:
        n = len(helps[s.name])
        rows.append({"source": s.name, "monthly_cost": s.monthly_cost, "techniques": n, "unique": len(only[s.name]),
                     "cost_per_technique": round(s.monthly_cost / n, 2) if n else None, "normalized": s.normalized})
    return sorted(rows, key=lambda r: (-r["unique"], -r["techniques"]))


def recommendations(results, top=10):
    """Missing (source, channel) pairs ranked by how many threat-model techniques they would move forward."""
    gain = defaultdict(set)
    for tid, r in results.items():
        if r["status"] in (NONE, PARTIAL):
            for ref in r["missing"]:
                gain[(ref.source, ref.channel, ref.component)].add(tid)
    ranked = sorted(gain.items(), key=lambda kv: -len(kv[1]))[:top]
    return [{"source": k[0], "channel": k[1], "component": k[2], "techniques": sorted(v)} for k, v in ranked]
