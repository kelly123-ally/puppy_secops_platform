from __future__ import annotations

from typing import Any, Dict
import re

ALLOWED_INTENTS = {"delivery", "control", "unknown"}
ALLOWED_SITES = {"zone_a", "zone_b", "zone_c", "zone_d", "dock"}
ALLOWED_CARGO = {"medical", "food", "supply", "repair", "document", "battery"}

HARD_BLOCK_REASONS = {
    "target_robot_mentioned_in_text",
    "dangerous_control_phrase",
    "forbidden_area_requested",
    "natural_language_control_not_allowed",
    "control_action_present",
    "target_robot_present",
}


def validate_task_candidate(candidate: Dict[str, Any], raw_text: str, username: str) -> Dict[str, Any]:
    reasons = []

    intent_type = candidate.get("intent_type")
    site = candidate.get("site")
    cargo_type = candidate.get("cargo_type")
    priority = candidate.get("priority")
    control_action = candidate.get("control_action")
    target_robot = candidate.get("target_robot")

    confirmation_reasons = list(candidate.get("confirmation_reasons") or [])
    if candidate.get("needs_confirmation"):
        reasons.extend(confirmation_reasons or ["candidate_needs_confirmation"])

    # 原始自然语言高风险表达兜底检查：即使大模型漏抽字段，也不能放过
    # “指定具体机器狗 + 绕过安全策略 + 禁区/直接控制”等越权表达。
    if re.search(r"\bdog\s*\d+\b|狗\s*\d+|机器狗\s*\d+|机器人\s*\d+|终端\s*\d+", raw_text, re.IGNORECASE):
        reasons.append("target_robot_mentioned_in_text")

    dangerous_control_words = [
        "绕过安全", "绕过策略", "绕过认证", "不要经过安全", "不经过安全",
        "直接执行控制命令", "直接控制", "暂停", "离线", "下线", "吊销",
        "恢复证书", "清空任务", "关闭安全", "关闭策略",
    ]
    if any(word in raw_text for word in dangerous_control_words):
        reasons.append("dangerous_control_phrase")

    forbidden_words = ["禁区", "禁止区域", "forbidden", "forbidden_area", "restricted"]
    if any(word in raw_text for word in forbidden_words):
        reasons.append("forbidden_area_requested")

    if intent_type not in ALLOWED_INTENTS:
        reasons.append("invalid_intent_type")

    # 自然语言入口当前只允许配送类任务
    if intent_type == "control":
        reasons.append("natural_language_control_not_allowed")

    if intent_type == "unknown":
        reasons.append("intent_not_clear")

    # 如果模型识别出了控制字段，也直接阻断
    if control_action:
        reasons.append("control_action_present")

    if target_robot:
        reasons.append("target_robot_present")

    # 只有 delivery 才继续检查业务字段
    if intent_type == "delivery":
        if site not in ALLOWED_SITES:
            reasons.append("invalid_site")

        if cargo_type not in ALLOWED_CARGO:
            reasons.append("invalid_cargo_type")

        if not isinstance(priority, int):
            reasons.append("priority_not_int")
        elif not (1 <= priority <= 5):
            reasons.append("priority_out_of_range")

        if candidate.get("x") is None or candidate.get("y") is None:
            reasons.append("missing_coordinates")

    final_task = {
        "task_id": candidate.get("task_id"),
        "site": candidate.get("site"),
        "x": candidate.get("x"),
        "y": candidate.get("y"),
        "priority": candidate.get("priority"),
        "cargo_type": candidate.get("cargo_type"),
        "note": candidate.get("note", raw_text),
        "requested_by": username,
        "source": candidate.get("source", "qwen_api"),
    }

    audit_candidate = {
        "task_id": candidate.get("task_id"),
        "intent_type": candidate.get("intent_type"),
        "site": candidate.get("site"),
        "priority": candidate.get("priority"),
        "cargo_type": candidate.get("cargo_type"),
        "control_action": candidate.get("control_action"),
        "target_robot": candidate.get("target_robot"),
        "needs_confirmation": candidate.get("needs_confirmation", False),
        "confirmation_reasons": candidate.get("confirmation_reasons", []),
        "source": candidate.get("source", "qwen_api"),
    }

    hard_reasons = [r for r in reasons if r in HARD_BLOCK_REASONS]

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
        "reasons": reasons,
        "final_task": final_task,
        "audit_candidate": audit_candidate,
    }
