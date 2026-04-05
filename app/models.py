from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class FirewallRule:
    """A normalized firewall rule from any vendor."""

    id: str
    name: str
    enabled: bool
    action: str  # "allow" | "deny" | "drop"
    src_zones: list[str]
    dst_zones: list[str]
    src_addrs: list[str]  # CIDRs or "any"
    dst_addrs: list[str]
    services: list[str]  # "tcp/80", "udp/53", "any"
    logging: bool
    position: int
    vendor_data: dict = field(default_factory=dict)


@dataclass
class Finding:
    """A single analysis finding."""

    finding_type: str  # "shadow", "conflict", "redundant", "permissive"
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    rule_ids: list[str]
    recommendation: str = ""


@dataclass
class AnalysisResult:
    """Complete result of analyzing a firewall config."""

    filename: str
    vendor: str
    imported_at: datetime = field(default_factory=datetime.now)
    rules: list[FirewallRule] = field(default_factory=list)
    shadowed: list[Finding] = field(default_factory=list)
    conflicts: list[Finding] = field(default_factory=list)
    redundant: list[Finding] = field(default_factory=list)
    permissive: list[Finding] = field(default_factory=list)

    def finding_count(self, category: str) -> int:
        data = getattr(self, category, [])
        return len(data) if isinstance(data, list) else 0

    def total_issues(self) -> int:
        return len(self.shadowed) + len(self.conflicts) + len(self.redundant) + len(self.permissive)

    def all_findings(self) -> list[Finding]:
        return self.shadowed + self.conflicts + self.redundant + self.permissive

    def to_export_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "vendor": self.vendor,
            "imported_at": self.imported_at.isoformat() if self.imported_at else None,
            "rule_count": len(self.rules),
            "rules": [
                {
                    "id": r.id, "name": r.name, "enabled": r.enabled,
                    "action": r.action, "src_zones": r.src_zones,
                    "dst_zones": r.dst_zones, "src_addrs": r.src_addrs,
                    "dst_addrs": r.dst_addrs, "services": r.services,
                    "logging": r.logging, "position": r.position,
                }
                for r in self.rules
            ],
            "findings": {
                "shadowed": [{"severity": f.severity, "title": f.title, "description": f.description, "rule_ids": f.rule_ids, "recommendation": f.recommendation} for f in self.shadowed],
                "conflicts": [{"severity": f.severity, "title": f.title, "description": f.description, "rule_ids": f.rule_ids, "recommendation": f.recommendation} for f in self.conflicts],
                "redundant": [{"severity": f.severity, "title": f.title, "description": f.description, "rule_ids": f.rule_ids, "recommendation": f.recommendation} for f in self.redundant],
                "permissive": [{"severity": f.severity, "title": f.title, "description": f.description, "rule_ids": f.rule_ids, "recommendation": f.recommendation} for f in self.permissive],
            },
        }
