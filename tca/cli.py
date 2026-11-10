"""Command line.

python -m tca.cli --inventory examples/inventory.yml (--layer L.json | --group "Volt Typhoon" | --techniques T1003.006,T1490)
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from . import attack, coverage

COLORS = {coverage.FULL: "#2e7d32", coverage.PARTIAL: "#f9a825", coverage.NONE: "#c62828", coverage.NO_GUIDANCE: "#9e9e9e"}


def threat_model(args, stix):
    ids = set()
    for layer in args.layer or []:
        ids |= {t["techniqueID"] for t in json.loads(Path(layer).read_text())["techniques"]}
    for g in args.group or []:
        ids |= attack.group_techniques(stix, g)
    if args.techniques:
        ids |= {t.strip() for t in args.techniques.split(",") if t.strip()}
    if not ids:
        raise SystemExit("give a threat model: --layer, --group or --techniques")
    return ids


def markdown(title, results, values, recs, sources):
    c = Counter(r["status"] for r in results.values())
    scored = len(results) - c[coverage.NO_GUIDANCE]

    def pct(n):
        return f"{(100 * n / scored):.0f}%" if scored else "n/a"

    total_cost = sum(s.monthly_cost for s in sources)
    out = [f"# Telemetry coverage: {title}", "",
           f"Threat model: **{len(results)} techniques** ({scored} with ATT&CK detection guidance for the platforms in scope).", "",
           "| Coverage | Techniques | Share |", "| --- | --- | --- |",
           f"| Full (every signal an analytic needs is collected) | {c[coverage.FULL]} | {pct(c[coverage.FULL])} |",
           f"| Partial (some signals missing) | {c[coverage.PARTIAL]} | {pct(c[coverage.PARTIAL])} |",
           f"| None (blind spot) | {c[coverage.NONE]} | {pct(c[coverage.NONE])} |",
           f"| No ATT&CK guidance for in-scope platforms | {c[coverage.NO_GUIDANCE]} | – |", "",
           f"Monthly ingest cost of the inventory: **${total_cost:,.0f}**.", "",
           "## Blind spots and partial coverage", "", "| Technique | Name | Status | Missing signals |", "| --- | --- | --- | --- |"]
    for tid, r in sorted(results.items(), key=lambda kv: (kv[1]["status"] != coverage.NONE, kv[0])):
        if r["status"] in (coverage.NONE, coverage.PARTIAL):
            miss = "; ".join(sorted({f"{m.source} ({m.channel})" for m in r["missing"]}))[:220]
            out.append(f"| {tid} | {r['name']} | {r['status']} | {miss} |")
    out += ["", "## Highest-value additions", "", "Collecting these signals moves the most threat-model techniques toward full coverage:", "",
            "| Log source | Channel / event | Data component | Techniques helped |", "| --- | --- | --- | --- |"]
    for r in recs:
        out.append(f"| {r['source']} | {r['channel'][:70]} | {r['component']} | {len(r['techniques'])}: {', '.join(r['techniques'][:6])}{'…' if len(r['techniques']) > 6 else ''} |")
    out += ["", "## Cost versus value per source", "",
            "| Source | Monthly cost | Techniques it enables | Only source for | Cost per technique | Normalized schema |",
            "| --- | --- | --- | --- | --- | --- |"]
    for v in values:
        cpt = f"${v['cost_per_technique']:,.2f}" if v["cost_per_technique"] is not None else "– (no threat-model value)"
        out.append(f"| {v['source']} | ${v['monthly_cost']:,.0f} | {v['techniques']} | {v['unique']} | {cpt} | {'yes' if v['normalized'] else 'no'} |")
    out += ["", "Sources with zero unique techniques and a high cost are candidates for filtering, sampling or a cheaper storage tier; "
            "sources that are the only coverage for several techniques are critical and need health monitoring.", ""]
    return "\n".join(out)


def layer(title, results):
    return {"name": f"Coverage: {title}", "versions": {"layer": "4.5", "navigator": "5.1.0"}, "domain": "enterprise-attack",
            "techniques": [{"techniqueID": tid, "color": COLORS[r["status"]], "comment": r["status"]} for tid, r in results.items()],
            "legendItems": [{"label": k, "color": v} for k, v in COLORS.items()]}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attack", default="data/enterprise-attack.json")
    p.add_argument("--inventory", required=True)
    p.add_argument("--layer", action="append")
    p.add_argument("--group", action="append")
    p.add_argument("--techniques")
    p.add_argument("--title", default="threat model")
    p.add_argument("--out", default="reports")
    a = p.parse_args(argv)
    stix = Path(a.attack)
    if not stix.exists():
        attack.fetch(stix)
    techniques = attack.load(stix)
    platforms, sources = coverage.load_inventory(a.inventory)
    results = coverage.score(techniques, threat_model(a, stix), platforms, sources)
    values = coverage.source_value(results, sources)
    recs = coverage.recommendations(results)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    slug = a.title.lower().replace(" ", "-")
    (out / f"{slug}.md").write_text(markdown(a.title, results, values, recs, sources), encoding="utf-8")
    (out / f"{slug}-layer.json").write_text(json.dumps(layer(a.title, results), indent=2))
    c = Counter(r["status"] for r in results.values())
    print(f"{a.title}: full={c['full']} partial={c['partial']} none={c['none']} no-guidance={c['no-guidance']} -> {out / (slug + '.md')}")
    return results


if __name__ == "__main__":
    main()
