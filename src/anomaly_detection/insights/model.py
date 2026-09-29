from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Category(str, Enum):
    reliability = "reliability"
    capacity = "capacity"
    efficiency = "efficiency"
    security = "security"
    configuration = "configuration"


SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
MAX_AFFECTED = 50


@dataclass
class Affected:
    namespace: str
    name: str
    detail: str = ""
    kind: str = ""


@dataclass
class Insight:
    id: str
    category: Category
    severity: str
    title: str
    summary: str
    impact: str
    recommendation: str
    fix: str = ""
    affected: list[Affected] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def affected_count(self) -> int:
        return len(self.affected)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["affected_count"] = self.affected_count
        data["affected"] = data["affected"][:MAX_AFFECTED]
        return data
