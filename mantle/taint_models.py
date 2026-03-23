"""Core data structures for taint analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mantle.taint_rules import TaintLabel, TrustPolicy


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class TaintFinding:
    """A single taint-analysis finding (source -> sink)."""

    severity: Severity
    title: str
    description: str
    source_event: dict[str, Any] | None = None
    sink_event: dict[str, Any] | None = None
    taint_chain: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_event_seq": (self.source_event or {}).get("seq"),
            "sink_event_seq": (self.sink_event or {}).get("seq"),
            "taint_chain": self.taint_chain,
        }


@dataclass
class TaintFlow:
    """An edge in the taint propagation graph."""

    from_label: str
    to_label: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_label,
            "to": self.to_label,
            "reason": self.reason,
        }


@dataclass
class TaintReport:
    """Complete taint analysis result."""

    trust_policy: TrustPolicy
    findings: list[TaintFinding] = field(default_factory=list)
    tainted_entities: list[dict[str, Any]] = field(default_factory=list)
    taint_flows: list[TaintFlow] = field(default_factory=list)
    agent_created_files: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_policy": self.trust_policy.value,
            "findings": [f.to_dict() for f in self.findings],
            "tainted_entities": self.tainted_entities,
            "taint_flows": [f.to_dict() for f in self.taint_flows],
            "agent_created_files": self.agent_created_files,
            "summary": self.summary,
            "finding_counts": {
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "warning": sum(1 for f in self.findings if f.severity == Severity.WARNING),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
        }


@dataclass
class TaintState:
    """Mutable state used during forward propagation."""

    agent_created_files: set[str] = field(default_factory=set)
    tainted_files: dict[str, TaintLabel] = field(default_factory=dict)
    tainted_tool_results: dict[str, TaintLabel] = field(default_factory=dict)
    taint_provenance: dict[str, str] = field(default_factory=dict)
    findings: list[TaintFinding] = field(default_factory=list)
    flows: list[TaintFlow] = field(default_factory=list)
    endpoint_taint: dict[str, TaintLabel] = field(default_factory=dict)
    mitm_endpoints: set[str] = field(default_factory=set)
