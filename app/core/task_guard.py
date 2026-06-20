from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .taskguard_taxonomy import (
    normalize_taskguard_tags,
    taskguard_decision_from_tags,
    taskguard_risk_level,
    taskguard_risk_score,
)

ALLOWED_INTENTS = {"delivery", "control", "unknown"}
ALLOWED_SITES = {"zone_a", "zone_b", "zone_c", "zone_d", "dock"}
ALLOWED_CARGO = {"medical", "food", "supply", "repair", "document", "battery"}

SITE_HINTS = {
    "zone_a": ["a区", "一区", "1号区域", "一号区域", "zone a", "zone_a"],
    "zone_b": ["b区", "二区", "2号区域", "二号区域", "zone b", "zone_b"],
    "zone_c": ["c区", "三区", "3号区域", "三号区域", "zone c", "zone_c"],
    "zone_d": ["d区", "四区", "4号区域", "四号区域", "zone d", "zone_d"],
    "dock": ["充电桩", "停靠点", "dock", "基地", "返航点"],
}

CARGO_HINTS = {
    "medical": ["急救", "医疗", "药", "医药", "救援", "medical", "first aid"],
    "document": ["文件", "资料", "文档", "document"],
    "food": ["食品", "食物", "餐", "food"],
    "repair": ["维修", "工具", "repair"],
    "battery": ["电池", "battery"],
    "supply": ["补给", "物资", "supply"],
}


def _has_any(text: str, words: List[str]) -> bool:
    return any(word.lower() in text.lower() for word in words)


def _first_site_mentioned(raw_text: str) -> Optional[str]:
    lower = raw_text.lower()
    for site, hints in SITE_HINTS.items():
        if any(h in lower for h in hints):
            return site
    return None


def _first_cargo_mentioned(raw_text: str) -> Optional[str]:
    lower = raw_text.lower()
    for cargo, hints in CARGO_HINTS.items():
        if any(h in lower for h in hints):
            return cargo
    return None


def _dedup(items: List[str]) -> List[str]:
    return list(dict.fromkeys(items))


def validate_task_candidate(candidate: Dict[str, Any], raw_text: str, username: str) -> Dict[str, Any]:
    """TaskGuard-S 规则标注器。

    当前函数仍是规则版/弱标注器；后续训练出的 TaskGuard-S 模型会学习这里输出的
    decision + risk_tags。标签已合并为 6 类：
    task_unclear / unauthorized_operation / restricted_target / dangerous_action /
    semantic_mismatch / complex_task。
    """
    reasons: List[str] = []
    raw = raw_text or ""

    intent_type = candidate.get("intent_type")
    site = candidate.get("site")
    cargo_type = candidate.get("cargo_type")
    priority = candidate.get("priority")
    control_action = candidate.get("control_action")
    target_robot = candidate.get("target_robot")

    confirmation_reasons = list(candidate.get("confirmation_reasons") or [])
    if candidate.get("needs_confirmation"):
        reasons.extend(confirmation_reasons or ["candidate_needs_confirmation"])

    # 条件型/触发型任务：当前版本不自动创建条件分支，进入人工确认。
    if re.search(r"(如果|若|一旦|当).{0,20}(就|则|请|派|让|执行|自动)", raw):
        reasons.append("unsupported_if_then_task")

    # 用户指定具体机器狗：不是直接阻断，而是业务越权/调度约束，需要确认。
    if re.search(r"\bdog\s*\d+\b|狗\s*\d+|机器狗\s*\d+|机器人\s*\d+|终端\s*\d+", raw, re.IGNORECASE):
        reasons.append("target_robot_mentioned_in_text")

    if target_robot:
        reasons.append("target_robot_present")

    # 业务越权表达：交给 TaskGuard-S，不再由 RawShield 处理。
    privilege_words = [
        "管理员模式", "最高权限", "超级用户", "root权限", "root 权限",
        "强制派", "强制执行", "直接强制", "越权", "提权",
        "admin mode", "administrator mode", "root permission", "force execute",
    ]
    if _has_any(raw, privilege_words):
        reasons.append("privilege_escalation_phrase")

    priority_abuse_words = ["最高优先级", "最高级别", "优先级最高", "立刻置顶", "强制置顶"]
    if _has_any(raw, priority_abuse_words):
        reasons.append("priority_abuse_phrase")

    # 危险动作/关闭安全/逃避审计：TaskGuard-S 负责，直接高风险。
    dangerous_control_words = [
        "关闭安全", "关闭保护", "关闭安全检查", "关闭任务审计", "关闭审计", "关闭日志",
        "禁用安全", "禁用审计", "禁用日志", "不要记录", "不记录日志", "不要写入审计",
        "不要审计", "不写日志", "秘密执行", "暗中执行", "不要触发安全闸门",
        "不触发安全闸门", "别触发安全闸门", "绕过安全", "绕过闸门", "绕过检查",
        "绕过审计", "跳过安全", "跳过检查", "直接执行控制命令", "直接控制",
        "暂停", "离线", "下线", "吊销", "恢复证书", "清空任务", "删除日志",
        "do not log", "don't log", "do not audit", "bypass security", "disable security",
        "disable audit", "disable logging", "secretly execute",
    ]
    if _has_any(raw, dangerous_control_words):
        reasons.append("dangerous_control_phrase")

    forbidden_words = [
        "禁区", "禁止区域", "未授权区域", "受限区域", "restricted area",
        "restricted", "forbidden", "forbidden_area",
    ]
    if _has_any(raw, forbidden_words):
        reasons.append("forbidden_area_requested")

    if intent_type not in ALLOWED_INTENTS:
        reasons.append("invalid_intent_type")

    # 自然语言入口当前只允许配送类任务；控制类动作由控制台/安全通道处理。
    if intent_type == "control":
        reasons.append("natural_language_control_not_allowed")

    if intent_type == "unknown":
        reasons.append("intent_not_clear")

    if control_action:
        reasons.append("control_action_present")

    if intent_type == "delivery":
        if site not in ALLOWED_SITES:
            # 如果原文包含禁区/受限区域，归入 restricted_target；否则属于任务不清楚。
            if _has_any(raw, forbidden_words) or str(site).lower() in {"forbidden", "forbidden_area", "restricted"}:
                reasons.append("invalid_site")
            else:
                reasons.append("missing_site")

        if cargo_type not in ALLOWED_CARGO:
            reasons.append("missing_cargo_type")

        if not isinstance(priority, int):
            reasons.append("priority_not_int")
        elif not (1 <= priority <= 5):
            reasons.append("priority_out_of_range")

        if candidate.get("x") is None or candidate.get("y") is None:
            reasons.append("missing_coordinates")

        # 原文与结构化结果不一致：这是智能体解析可靠性风险。
        raw_site = _first_site_mentioned(raw)
        if raw_site and site in ALLOWED_SITES and raw_site != site:
            reasons.append("site_mismatch")

        raw_cargo = _first_cargo_mentioned(raw)
        if raw_cargo and cargo_type in ALLOWED_CARGO and raw_cargo != cargo_type:
            reasons.append("cargo_mismatch")

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

    reasons = _dedup(reasons)
    risk_tags = normalize_taskguard_tags(reasons, ir_type="single_task", mode="single")
    decision = taskguard_decision_from_tags(risk_tags)
    risk_level = taskguard_risk_level(decision, risk_tags)
    risk_score = taskguard_risk_score(risk_tags, decision)

    return {
        "decision": decision,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_tags": risk_tags,
        "reasons": reasons,
        "final_task": final_task,
        "audit_candidate": audit_candidate,
    }
