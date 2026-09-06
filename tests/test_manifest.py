from pathlib import Path
from skillcage.manifest import load_manifest, parse_frontmatter


def _skill(tmp_path, body):
    d = tmp_path / "s"
    d.mkdir()
    (d / "SKILL.md").write_text(body)
    return d


def test_parse_permissions(tmp_path):
    d = _skill(tmp_path,
        "---\nname: reporter\n"
        "description: monthly report\n"
        "permissions:\n"
        "  mcp:\n    qonto: [list_transactions, list_labels]\n"
        "  network: [api.example.com]\n"
        "  env: [TZ]\n"
        "  tools: [Read, Bash]\n---\n# x\n")
    m = load_manifest(d)
    assert m.name == "reporter"
    assert m.mcp == {"qonto": ["list_transactions", "list_labels"]}
    assert m.network == ["api.example.com"]
    assert m.tools == ["Read", "Bash"]


def test_missing_frontmatter(tmp_path):
    d = _skill(tmp_path, "# just a heading\n")
    m = load_manifest(d)
    assert m.mcp == {}
    assert m.tools == []


def test_allowed_tools_string_form(tmp_path):
    d = _skill(tmp_path,
        "---\nname: t\ndescription: d\nallowed-tools: Read, Grep, mcp__qonto__x\n---\n#x\n")
    m = load_manifest(d)
    assert "Read" in m.tools and "Grep" in m.tools
    assert "mcp__qonto__x" not in m.tools
