from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional


TASKGUARD_SCHEMA_VERSION = "taskguard"

TASKGUARD_RISK_TAGS = [
    "task_unclear",
    "unauthorized_operation",
    "restricted_target",
    "dangerous_action",
    "semantic_mismatch",
    "complex_task",
]

# 精简后的 TaskGuard-S 训练标签体系：
# - RawShield 只识别 prompt injection / jailbreak，不承担业务语义风险。
# - TaskGuard-S 统一判断普通任务和长难句任务的语义风险。
REASON_TO_TASKGUARD_TAG = {
    # 任务不清楚 / 字段不完整 / 暂不支持
    "candidate_needs_confirmation": "task_unclear",
    "missing_required_field": "task_unclear",
    "missing_intent_type": "task_unclear",
    "missing_site": "task_unclear",
    "missing_cargo_type": "task_unclear",
    "invalid_intent_type": "task_unclear",
    "intent_not_clear": "task_unclear",
    "invalid_cargo_type": "task_unclear",
    "priority_not_int": "task_unclear",
    "priority_out_of_range": "task_unclear",
    "missing_coordinates": "task_unclear",
    "unsupported_if_then_task": "task_unclear",
    "unsupported_condition": "task_unclear",
    "empty_plan_steps": "task_unclear",
    "invalid_plan_mode": "task_unclear",
    "duplicate_step_id": "task_unclear",
    "unknown_dependency": "task_unclear",

    # 越权操作 / 调度权限异常
    "target_robot_mentioned_in_text": "unauthorized_operation",
    "target_robot_present": "unauthorized_operation",
    "privilege_escalation_phrase": "unauthorized_operation",
    "priority_abuse_phrase": "unauthorized_operation",
    "force_execution_phrase": "unauthorized_operation",

    # 受限目标
    "forbidden_area_requested": "restricted_target",
    "invalid_site": "restricted_target",

    # 危险动作 / 关闭安全 / 逃避审计 / 控制类动作
    "dangerous_control_phrase": "dangerous_action",
    "safety_bypass_phrase": "dangerous_action",
    "audit_evasion_phrase": "dangerous_action",
    "natural_language_control_not_allowed": "dangerous_action",
    "control_action_present": "dangerous_action",

    # 原文与结构化结果不一致
    "nl_struct_mismatch": "semantic_mismatch",
    "site_mismatch": "semantic_mismatch",
    "cargo_mismatch": "semantic_mismatch",

    # 长难句/多步计划
    "complex_task": "complex_task",
    "parallel_plan_requires_confirmation": "complex_task",
    "sequential_plan_requires_confirmation": "complex_task",
    "multi_step_plan": "complex_task",
    "too_many_steps": "complex_task",
    "plan_has_cycle_dependency": "complex_task",
    "plan_step_needs_confirmation": "complex_task",
    "plan_contains_forbidden_or_dangerous_step": "complex_task",
    "plan_step_invalid": "complex_task",
}

HIGH_RISK_TAGS = {
    "restricted_target",
    "dangerous_action",
    "semantic_mismatch",
}

MEDIUM_RISK_TAGS = {
    "task_unclear",
    "unauthorized_operation",
    "complex_task",
}

RISK_SCORE_BY_TAG = {
    "task_unclear": 0.55,
    "unauthorized_operation": 0.60,
    "restricted_target": 0.90,
    "dangerous_action": 0.90,
    "semantic_mismatch": 0.85,
    "complex_task": 0.55,
}

RUNTIME_FIELDS = {
    "task_id",
    "plan_id",
    "lease_id",
    "assigned_robot",
    "robot_id",
    "status",
    "created_at",
    "updated_at",
    "confirmed_at",
    "confirmed_by",
    "plan_hash",
    "guard",
    "source",
    "requested_by",
    "battery",
    "x",
    "y",
}

SEMANTIC_KEEP_FIELDS = {
    "ir_type",
    "mode",
    "raw_text",
    "requires_confirmation",
    "steps",
    "single_task",
    "intent_type",
    "intent",
    "site",
    "priority",
    "cargo_type",
    "control_action",
    "target_robot",
    "needs_confirmation",
    "confirmation_reasons",
    "depends_on",
    "assignee",
    "step_id",
    "note",
}


def normalize_taskguard_tags(
    reasons: Iterable[str] | None,
    *,
    ir_type: Optional[str] = None,
    mode: Optional[str] = None,
) -> List[str]:
    tags: List[str] = []

    for reason in reasons or []:
        tag = REASON_TO_TASKGUARD_TAG.get(str(reason), str(reason))
        if tag in TASKGUARD_RISK_TAGS and tag not in tags:
            tags.append(tag)

    # 长难句/计划统一只增加 complex_task，不再区分 parallel/sequential/same_robot 等细标签。
    if ir_type == "plan" or mode in {"parallel", "sequential"}:
        if "complex_task" not in tags:
            tags.append("complex_task")

    return tags


def taskguard_risk_score(risk_tags: Iterable[str] | None, decision: str = "allow") -> float:
    tags = list(risk_tags or [])
    if not tags:
        if decision == "block":
            return 0.90
        if decision == "need_confirmation":
            return 0.55
        return 0.0
    return round(max(RISK_SCORE_BY_TAG.get(tag, 0.55) for tag in tags), 4)


def taskguard_risk_level(decision: str, risk_tags: Iterable[str] | None = None) -> str:
    tags = set(risk_tags or [])
    if decision == "block" or tags & HIGH_RISK_TAGS:
        return "high"
    if decision == "need_confirmation" or tags & MEDIUM_RISK_TAGS:
        return "medium"
    return "low"


def taskguard_decision_from_tags(risk_tags: Iterable[str] | None) -> str:
    tags = set(risk_tags or [])
    if tags & HIGH_RISK_TAGS:
        return "block"
    if tags & MEDIUM_RISK_TAGS:
        return "need_confirmation"
    return "allow"


def _clean_assignee(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    t = value.get("type")
    # 只保留语义约束，不保留实际调度结果。
    if t == "same_as":
        return {"type": "same_as", "same_as_step": value.get("same_as_step")}
    if t == "explicit":
        return {"type": "explicit", "robot_id": value.get("robot_id")}
    return {"type": t or "auto"}


def clean_taskguard_ir(obj: Any) -> Any:
    """清洗 TaskGuard-S 训练输入，去掉 task_id/lease/status 等运行时字段。"""
    if isinstance(obj, list):
        return [clean_taskguard_ir(item) for item in obj]
    if not isinstance(obj, dict):
        return obj

    cleaned: Dict[str, Any] = {}
    for key, value in obj.items():
        if key in RUNTIME_FIELDS:
            continue
        if key not in SEMANTIC_KEEP_FIELDS:
            continue
        if key == "assignee":
            cleaned[key] = _clean_assignee(value)
        else:
            cleaned[key] = clean_taskguard_ir(value)
    return cleaned


def build_taskguard_record(
    *,
    raw_text: str,
    ir_type: str,
    mode: str,
    decision: str,
    reasons: Iterable[str] | None,
    parsed_ir: Dict[str, Any] | None,
    username: str,
    step_results: Optional[List[Dict[str, Any]]] = None,
    final_task: Optional[Dict[str, Any]] = None,
    plan_id: Optional[str] = None,
) -> Dict[str, Any]:
    risk_tags = normalize_taskguard_tags(reasons, ir_type=ir_type, mode=mode)
    normalized_decision = decision
    tag_decision = taskguard_decision_from_tags(risk_tags)
    if tag_decision == "block":
        normalized_decision = "block"
    elif tag_decision == "need_confirmation" and normalized_decision == "allow":
        normalized_decision = "need_confirmation"

    risk_level = taskguard_risk_level(normalized_decision, risk_tags)
    risk_score = taskguard_risk_score(risk_tags, normalized_decision)

    record: Dict[str, Any] = {
        "stage": "TaskGuard",
        "guard_engine": "TaskGuard-S",
        "label_schema": TASKGUARD_SCHEMA_VERSION,
        "raw_text": raw_text,
        "ir_type": ir_type,
        "mode": mode,
        "decision": normalized_decision,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_tags": risk_tags,
        "reasons": list(dict.fromkeys(reasons or [])),
        "parsed_ir": clean_taskguard_ir(parsed_ir or {}),
        "username": username,
    }
    if step_results is not None:
        record["step_results"] = step_results
    if final_task is not None:
        record["final_task"] = clean_taskguard_ir(final_task)
    if plan_id:
        record["plan_id"] = plan_id
    return record
