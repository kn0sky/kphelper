from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from .formatting import UNKNOWN


@dataclass(frozen=True)
class Finding:
    status: str
    value: Any = None
    detail: Optional[str] = None
    source: Optional[str] = None

    @classmethod
    def from_value(cls, value, source=None):
        return cls(status=str(value), source=source)

    @classmethod
    def from_mapping(cls, result):
        if isinstance(result, cls):
            return result
        if not isinstance(result, Mapping):
            return cls.from_value(result)
        return cls(
            status=result.get("status", UNKNOWN),
            value=result.get("value"),
            detail=result.get("detail"),
            source=result.get("source"),
        )

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        result = {"status": self.status}
        if self.value is not None:
            result["value"] = self.value
        if self.detail:
            result["detail"] = self.detail
        if self.source:
            result["source"] = self.source
        return result


@dataclass(frozen=True)
class RuntimeProbeReport:
    findings: Dict[str, Finding]
    symbols: Dict[str, int]

    def to_dict(self):
        result = {name: finding.to_dict() for name, finding in self.findings.items()}
        result["symbols"] = dict(self.symbols)
        return result
