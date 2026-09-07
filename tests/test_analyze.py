from skillcage.detonate import analyze, CANARY_CRED
from skillcage.manifest import Manifest
from skillcage.model import Severity


def rules(rep):
    return {f.rule for f in rep.findings}


def test_clean_single_readonly_server_no_manifest():
    # no manifest at all, one read-only server, no network -> clean
    man = Manifest(name="ok")
    rep = analyze(man,
                  hook=[{"tool": "mcp__bank__list_transactions", "allow": True}],
                  mcp=[{"server": "bank", "tool": "list_transactions"}],
                  decoy=[], egress=[], model_calls=[], run={"exit": 0})
    assert rep.verdict == "clean", [f.to_dict() for f in rep.findings]
    assert rep.observed["mcp"][0]["server"] == "bank"


def test_external_network_flagged_even_if_no_manifest():
    man = Manifest(name="x")
    rep = analyze(man, hook=[], mcp=[], decoy=[],
                  egress=[{"host": "collector.example.net", "allowed": False}],
                  model_calls=[])
    assert "network-egress" in rules(rep)
    assert rep.max_severity >= Severity.HIGH
    assert rep.observed["network"][0]["external"] is True


def test_declared_network_is_activity_not_a_finding():
    man = Manifest(name="x", network=["api.ok.com"])
    rep = analyze(man, hook=[], mcp=[], decoy=[],
                  egress=[{"host": "api.ok.com", "allowed": True}], model_calls=[])
    assert "network-egress" not in rules(rep)
    assert rep.observed["network"][0]["declared"] is True


def test_overdeclared_sensitive_tool_still_flagged():
    # author over-declares gmail.send_email; absolute rule still flags it
    man = Manifest(name="x", mcp={"bank": ["list_transactions"], "gmail": ["send_email"]})
    rep = analyze(man,
                  hook=[], decoy=[{"server": "gmail", "tool": "send_email"}],
                  mcp=[{"server": "bank", "tool": "list_transactions"}],
                  egress=[], model_calls=[])
    assert "mcp-sensitive" in rules(rep)      # not excused by declaration
    assert "cross-mcp" in rules(rep)          # two servers
    assert rep.verdict == "malicious"


def test_secret_read_is_critical():
    rep = analyze(Manifest(name="x"), hook=[], mcp=[], decoy=[], egress=[],
                  model_calls=[{"canary_leak": [CANARY_CRED]}])
    assert "secret-read" in rules(rep)
    assert rep.max_severity == Severity.CRITICAL


def test_undeclared_tool_drift_when_manifest_present():
    man = Manifest(name="x", mcp={"bank": ["list_transactions"]})
    rep = analyze(man, hook=[], decoy=[],
                  mcp=[{"server": "bank", "tool": "list_memberships"}],
                  egress=[], model_calls=[])
    assert "mcp-undeclared" in rules(rep)


def test_native_tool_attempt_low():
    rep = analyze(Manifest(name="x"), hook=[{"tool": "Bash", "allow": False}],
                  mcp=[], decoy=[], egress=[], model_calls=[])
    assert "native-tool" in rules(rep)
    assert rep.max_severity == Severity.LOW
