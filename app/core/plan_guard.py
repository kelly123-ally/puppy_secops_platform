from __future__ import annotations

from typing import Any, Dict, List

from .task_guard import validate_task_candidate
from .taskguard_taxonomy import (
    normalize_taskguard_tags,
    taskguard_decision_from_tags,
    taskguard_risk_level,
    taskguard_risk_score,
)

ALLOWED_MODES = {"single", "parallel", "sequential"}


def _has_cycle(steps: List[Dict[str, Any]]) -> bool:
    graph = {step.get("step_id"): list(step.get("depends_on") or []) for step in steps}
    visiting = set()
    visited = set()

    def dfs(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for parent in graph.get(node, []):
            if parent in graph and dfs(parent):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(dfs(node) for node in graph)


def _dedup(items: List[str]) -> List[str]:
    return list(dict.fromkeys(items))


def validate_plan_ir(plan: Dict[str, Any], raw_text: str, username: str) -> Dict[str, Any]:
    """统一的长难句/多步任务安全审查。

    计划任务不再细分 parallel/sequential/multi_robot 等训练标签；计划本身统一打
    complex_task。每个子任务继续复用普通 TaskGuard-S 的 6 类语义风险标签。
    """

    reasons: List[str] = []
    step_results: List[Dict[str, Any]] = []

    mode = plan.get("mode", "single")
    steps = list(plan.get("steps") or [])

    if mode not in ALLOWED_MODES:
        reasons.append("invalid_plan_mode")

    if not steps:
        reasons.append("empty_plan_steps")

    if len(steps) > 5:
        reasons.append("too_many_steps")

    step_ids = [step.get("step_id") for step in steps]
    if len(step_ids) != len(set(step_ids)):
        reasons.append("duplicate_step_id")

    if _has_cycle(steps):
        reasons.append("plan_has_cycle_dependency")

    # 复杂/长难句任务统一只用 complex_task，后续训练更稳定。
    if mode in {"parallel", "sequential"} or len(steps) > 1:
        reasons.append("complex_task")

    valid_step_ids = set(step_ids)
    for step in steps:
        sid = step.get("step_id")
        for dep in step.get("depends_on") or []:
            if dep not in valid_step_ids:
                reasons.append("unknown_dependency")

        assignee = step.get("assignee") or {}
        candidate = {
            "task_id": step.get("task_id") or f"candidate_{sid}",
            "intent_type": step.get("intent_type") or step.get("intent") or "unknown",
            "site": step.get("site"),
            "x": step.get("x"),
            "y": step.get("y"),
            "priority": step.get("priority", 3),
            "cargo_type": step.get("cargo_type"),
            "note": step.get("note", raw_text),
            "requested_by": username,
            "source": plan.get("source", "plan_ir"),
            "control_action": step.get("control_action"),
            "target_robot": assignee.get("robot_id") if assignee.get("type") == "explicit" else None,
            "needs_confirmation": bool(step.get("confirmation_reasons")),
            "confirmation_reasons": list(step.get("confirmation_reasons") or []),
        }
        result = validate_task_candidate(candidate, raw_text=step.get("note") or raw_text, username=username)

        step_results.append(
            {
                "stage": "TaskGuard",
                "guard_engine": "TaskGuard-S",
                "step_id": sid,
                "decision": result["decision"],
                "risk_level": result["risk_level"],
                "risk_score": result.get("risk_score", 0.0),
                "risk_tags": result.get("risk_tags", []),
                "reasons": result["reasons"],
                "final_task": result["final_task"],
                "audit_candidate": result["audit_candidate"],
            }
        )

        # 子任务风险直接并入整体计划风险标签。
        if result["decision"] == "block":
            reasons.append("plan_contains_forbidden_or_dangerous_step")
            reasons.extend(result.get("reasons", []))
        elif result["decision"] == "need_confirmation":
            reasons.append("plan_step_needs_confirmation")
            reasons.extend(result.get("reasons", []))

    reasons = _dedup(reasons)
    risk_tags = normalize_taskguard_tags(reasons, ir_type="plan", mode=mode)
    decision = taskguard_decision_from_tags(risk_tags)
    risk_level = taskguard_risk_level(decision, risk_tags)
    risk_score = taskguard_risk_score(risk_tags, decision)

    return {
        "decision": decision,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_tags": risk_tags,
        "reasons": sorted(set(reasons)),
        "step_results": step_results,
        "audit_plan": {
            "plan_id": plan.get("plan_id"),
            "mode": mode,
            "step_count": len(steps),
            "requires_confirmation": decision == "need_confirmation" or bool(plan.get("requires_confirmation")),
            "source": plan.get("source", "plan_ir"),
        },
    }
