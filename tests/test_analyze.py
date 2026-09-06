from skillcage.detonate import analyze
from skillcage.manifest import Manifest
from skillcage.model import Severity


def rules(rep):
    return {f.rule for f in rep.findings}


def test_clean_when_within_manifest():
    man = Manifest(name="ok", mcp={"qonto": ["list_transactions"]}, tools=["Read"])
    rep = analyze(man,
                  hook=[{"tool": "Read", "allow": True},
                        {"tool": "mcp__qonto__list_transactions", "allow": True}],
                  mcp=[{"server": "qonto", "tool": "list_transactions"}],
                  decoy=[], egress=[], model_calls=[], run={"exit": 0})
    assert rep.verdict == "clean", [f.to_dict() for f in rep.findings]


def test_undeclared_tool_within_server():
    man = Manifest(name="x", mcp={"qonto": ["list_transactions"]})
    rep = analyze(man, hook=[], mcp=[{"server": "qonto", "tool": "list_memberships"}],
                  decoy=[], egress=[], model_calls=[])
    assert "undeclared-mcp" in rules(rep)
    assert rep.max_severity >= Severity.HIGH


def test_cross_mcp_server():
    man = Manifest(name="x", mcp={"qonto": ["list_transactions"]})
    rep = analyze(man, hook=[{"tool": "mcp__gmail__send_email", "allow": True}],
                  mcp=[], decoy=[{"server": "gmail", "tool": "send_email"}],
                  egress=[], model_calls=[])
    assert "cross-mcp" in rules(rep)
    assert rep.verdict == "malicious"


def test_egress_blocked():
    man = Manifest(name="x", network=["api.ok.com"])
    rep = analyze(man, hook=[], mcp=[], decoy=[],
                  egress=[{"host": "evil.example", "allowed": False},
                          {"host": "api.ok.com", "allowed": True}],
                  model_calls=[])
    r = [f for f in rep.findings if f.rule == "egress"]
    assert r and "evil.example" in r[0].title


def test_canary_leak_is_critical():
    from skillcage.detonate import CANARY_CRED
    man = Manifest(name="x")
    rep = analyze(man, hook=[], mcp=[], decoy=[], egress=[],
                  model_calls=[{"canary_leak": [CANARY_CRED]}])
    assert "canary-leak" in rules(rep)
    assert rep.max_severity == Severity.CRITICAL


def test_native_tool_attempt_is_low_context():
    man = Manifest(name="x")
    rep = analyze(man, hook=[{"tool": "Bash", "allow": False}],
                  mcp=[], decoy=[], egress=[], model_calls=[])
    assert "native-tool-attempt" in rules(rep)
    assert rep.max_severity == Severity.LOW
