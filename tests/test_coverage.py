import pathlib

import yaml

from tca import attack, coverage

FIX = pathlib.Path(__file__).parent / "fixtures" / "mini-attack.json"


def inventory(tmp_path, sources):
    p = tmp_path / "inv.yml"
    p.write_text(yaml.safe_dump({"platforms": ["Windows"], "sources": sources}))
    return coverage.load_inventory(p)


def test_loader_resolves_strategy_to_log_sources():
    t = attack.load(FIX)
    assert set(t) == {"T1003.006", "T1490"}, "revoked techniques are dropped"
    assert t["T1003.006"].analytics[0].refs[0].event_codes() == {"4662"}


def test_missing_event_code_is_a_blind_spot(tmp_path):
    plat, src = inventory(tmp_path, [{"name": "WinEventLog:Security", "channels": ["4624", "4688"]}])
    r = coverage.score(attack.load(FIX), {"T1003.006"}, plat, src)
    assert r["T1003.006"]["status"] == coverage.NONE


def test_partial_when_one_of_two_signals_present(tmp_path):
    plat, src = inventory(tmp_path, [{"name": "WinEventLog:Security", "channels": ["4688"]}])
    r = coverage.score(attack.load(FIX), {"T1490"}, plat, src)
    assert r["T1490"]["status"] == coverage.PARTIAL
    assert [m.source for m in r["T1490"]["missing"]] == ["WinEventLog:Sysmon"]


def test_full_coverage_and_source_value(tmp_path):
    plat, src = inventory(tmp_path, [
        {"name": "WinEventLog:Security", "channels": "*", "daily_gb": 10, "cost_per_gb": 2},
        {"name": "WinEventLog:Sysmon", "channels": ["1"], "daily_gb": 5, "cost_per_gb": 2},
        {"name": "NSM:Firewall", "channels": "*", "daily_gb": 100, "cost_per_gb": 2}])
    r = coverage.score(attack.load(FIX), {"T1003.006", "T1490"}, plat, src)
    assert {v["status"] for v in r.values()} == {coverage.FULL}
    values = {v["source"]: v for v in coverage.source_value(r, src)}
    assert values["WinEventLog:Security"]["unique"] == 1          # only source for DCSync
    assert values["NSM:Firewall"]["techniques"] == 0 and values["NSM:Firewall"]["monthly_cost"] == 6000


def test_recommendations_rank_missing_signals(tmp_path):
    plat, src = inventory(tmp_path, [{"name": "WinEventLog:Security", "channels": ["4688"]}])
    r = coverage.score(attack.load(FIX), {"T1003.006", "T1490"}, plat, src)
    recs = coverage.recommendations(r)
    assert {(x["source"], x["channel"]) for x in recs} == {("WinEventLog:Security", "EventCode=4662"), ("WinEventLog:Sysmon", "EventCode=1")}


def test_group_threat_model_by_alias():
    assert attack.group_techniques(FIX, "EG") == {"T1490"}


def test_platform_filter_gives_no_guidance(tmp_path):
    p = tmp_path / "inv.yml"
    p.write_text(yaml.safe_dump({"platforms": ["Linux"], "sources": [{"name": "WinEventLog:Security"}]}))
    plat, src = coverage.load_inventory(p)
    r = coverage.score(attack.load(FIX), {"T1490"}, plat, src)
    assert r["T1490"]["status"] == coverage.NO_GUIDANCE
