from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


Point = Tuple[int, int]


@dataclass
class Robot:
    robot_id: str
    x: int
    y: int
    home: Point
    battery: float = 100.0
    status: str = "idle"
    current_task_id: Optional[str] = None
    current_lease_id: Optional[str] = None
    path: List[Point] = field(default_factory=list)
    last_heartbeat: float = 0.0
    offline: bool = False
    compromised: bool = False
    revoked: bool = False
    paused: bool = False
    speed_cells: int = 1
    payload_capacity: int = 5
    assigned_site: Optional[str] = None
    capability_tags: List[str] = field(default_factory=lambda: ["medical", "food", "repair"])
    zone_access: List[str] = field(default_factory=lambda: ["zone_a", "zone_b", "zone_c", "zone_d", "dock"])

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["path"] = list(self.path)
        return data


@dataclass
class Task:
    task_id: str
    site: str
    x: int
    y: int
    priority: int
    cargo_type: str
    note: str
    requested_by: str
    source: str
    status: str = "queued"
    assigned_robot: Optional[str] = None
    lease_id: Optional[str] = None
    created_at: float = 0.0
    updated_at: float = 0.0
    attempts: int = 0
    blocked: bool = False
    block_reason: Optional[str] = None
    plan_id: Optional[str] = None
    step_id: Optional[str] = None
    plan_mode: Optional[str] = None
    preferred_robot: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditEvent:
    ts: float
    level: str
    category: str
    title: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicySet:
    strict_mode: bool = True
    require_signed_commands: bool = True
    replay_protection: bool = True
    auto_revoke_compromised: bool = True
    enforce_lease_id: bool = True
    idempotent_completion: bool = True
    least_privilege_topics: bool = True
    heartbeat_timeout_sec: float = 8.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
