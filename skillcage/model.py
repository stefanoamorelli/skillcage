from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, s: str) -> "Severity":
        return {"info": cls.INFO, "low": cls.LOW, "medium": cls.MEDIUM,
                "high": cls.HIGH, "critical": cls.CRITICAL}.get(str(s).lower(), cls.MEDIUM)

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    rule: str
    severity: Severity
    title: str
    detail: str = ""
    evidence: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class Report:
    skill: str
    findings: list[Finding] = field(default_factory=list)
    observed: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def verdict(self) -> str:
        if self.error:
            return "error"
        s = self.max_severity
        if s >= Severity.HIGH:
            return "malicious"
        if s >= Severity.MEDIUM:
            return "suspicious"
        return "clean"

    def to_dict(self) -> dict:
        return {"skill": self.skill, "verdict": self.verdict,
                "max_severity": self.max_severity.label,
                "error": self.error, "observed": self.observed,
                "findings": [f.to_dict() for f in self.findings]}
