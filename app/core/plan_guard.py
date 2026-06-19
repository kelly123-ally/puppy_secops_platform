from __future__ import annotations

from typing import Any, Dict, List

from .task_guard import validate_task_candidate

HARD_PLAN_BLOCK_REASONS = {
    "too_many_steps",
    "plan_contains_control_step",
    "plan_contains_forbidden_or_dangerous_step",
    "plan_has_cycle_dependency",
    "plan_step_invalid",
}

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


def validate_plan_ir(plan: Dict[str, Any], raw_text: str, username: str) -> Dict[str, Any]:
    """计划级安全审查。

    当前版本只支持三类自然语言任务：
    - single：单任务
    - parallel：并行多任务
    - sequential：顺序多步骤任务

    “如果/若/一旦/当……则/就……”等条件型表达不会进入 PlanIR 自动执行链路，
    而是在 qwen_client 中降级为 need_confirmation，由操作员根据实时状态回传重新下发任务。
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

    # 复杂但安全的计划默认需要人工确认，确认后每个 step 单独生成 task_id/lease_id。
    if mode in {"parallel", "sequential"} or len(steps) > 1:
        reasons.append(f"{mode}_plan_requires_confirmation")

    valid_step_ids = set(step_ids)
    for step in steps:
        sid = step.get("step_id")
        for dep in step.get("depends_on") or []:
            if dep not in valid_step_ids:
                reasons.append("unknown_dependency")

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
            "target_robot": (step.get("assignee") or {}).get("robot_id") if (step.get("assignee") or {}).get("type") == "explicit" else None,
            "needs_confirmation": bool(step.get("confirmation_reasons")),
            "confirmation_reasons": list(step.get("confirmation_reasons") or []),
        }
        result = validate_task_candidate(candidate, raw_text=raw_text, username=username)
        step_results.append({
            "step_id": sid,
            "decision": result["decision"],
            "risk_level": result["risk_level"],
            "reasons": result["reasons"],
            "final_task": result["final_task"],
            "audit_candidate": result["audit_candidate"],
        })
        if result["decision"] == "block":
            reasons.append("plan_contains_forbidden_or_dangerous_step")
        elif result["decision"] == "need_confirmation":
            reasons.append("plan_step_needs_confirmation")

    hard_reasons = [r for r in reasons if r in HARD_PLAN_BLOCK_REASONS]
    if hard_reasons:
        decision = "block"
        risk_level = "high"
    elif reasons:
        decision = "need_confirmation"
        risk_level = "medium"
    else:
        decision = "allow"
        risk_level = "low"

    return {
        "decision": decision,
        "risk_level": risk_level,
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
