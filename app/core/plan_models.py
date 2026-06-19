from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class PlanStep:
    """一个长难句计划中的单个可执行步骤。

    注意：PlanStep 本身不等于真实 Task。只有当该 step 被激活并编译为 Task 后，
    才会进入原有的 LBC/LBSE 租约绑定流程。
    """

    step_id: str
    intent_type: str
    site: Optional[str]
    x: Optional[int]
    y: Optional[int]
    priority: int
    cargo_type: Optional[str]
    note: str
    assignee: Dict[str, Any] = field(default_factory=lambda: {"type": "auto"})
    depends_on: List[str] = field(default_factory=list)
    status: str = "pending"  # pending / queued / running / completed / failed
    task_id: Optional[str] = None
    lease_id: Optional[str] = None
    assigned_robot: Optional[str] = None
    confirmation_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Plan:
    """长难句任务计划。

    Plan 只负责表达编排关系，不直接授权机器狗执行。
    真正的执行授权由每个 Step 编译出的 Task 单独生成 lease_id。
    """

    plan_id: str
    ir_type: str
    mode: str  # single / parallel / sequential
    raw_text: str
    requested_by: str
    requires_confirmation: bool
    steps: List[PlanStep]
    status: str = "pending_confirmation"  # pending_confirmation / approved / running / completed / canceled / blocked
    reasons: List[str] = field(default_factory=list)
    plan_hash: Optional[str] = None
    created_at: float = 0.0
    confirmed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["steps"] = [step.to_dict() for step in self.steps]
        return data
