from __future__ import annotations

import itertools
import json
import os
from typing import Any, Dict

import httpx

from .nl_agent import SITE_MAP, infer_cargo, infer_priority, infer_site

_counter = itertools.count(1)

ALLOWED_SITES = set(SITE_MAP.keys())
ALLOWED_CARGO = {"medical", "food", "supply", "repair", "document", "battery"}
ALLOWED_INTENTS = {"delivery", "control", "unknown"}

SITE_ALIASES = {
    "zone_a": "zone_a", "a区": "zone_a", "a区域": "zone_a", "一区": "zone_a", "一号区域": "zone_a", "地区1": "zone_a", "1号区域": "zone_a",
    "zone_b": "zone_b", "b区": "zone_b", "b区域": "zone_b", "二区": "zone_b", "二号区域": "zone_b", "地区2": "zone_b", "2号区域": "zone_b",
    "zone_c": "zone_c", "c区": "zone_c", "c区域": "zone_c", "三区": "zone_c", "三号区域": "zone_c", "地区3": "zone_c", "3号区域": "zone_c",
    "zone_d": "zone_d", "d区": "zone_d", "d区域": "zone_d", "四区": "zone_d", "四号区域": "zone_d", "地区4": "zone_d", "4号区域": "zone_d",
    "dock": "dock", "充电站": "dock", "回充": "dock", "基地": "dock",
}

CARGO_ALIASES = {
    "medical": "medical", "医疗": "medical", "急救": "medical", "药": "medical", "医疗包": "medical", "急救包": "medical",
    "food": "food", "食物": "food", "食品": "food", "餐": "food",
    "supply": "supply", "补给": "supply", "物资": "supply", "用品": "supply",
    "repair": "repair", "维修": "repair", "工具": "repair", "修理": "repair",
    "document": "document", "文档": "document", "文件": "document", "资料": "document",
    "battery": "battery", "电池": "battery", "能源": "battery",
}


def _explicit_site_from_text(text: str) -> str | None:
    lowered = text.lower()
    compact = lowered.replace(" ", "").replace("　", "")
    raw_compact = text.replace(" ", "").replace("　", "")
    for token, site in SITE_ALIASES.items():
        token_l = token.lower()
        if token_l in lowered or token_l in compact or token in text or token in raw_compact:
            return site
    return None


def _explicit_cargo_from_text(text: str) -> str | None:
    lowered = text.lower()
    compact = lowered.replace(" ", "").replace("　", "")
    raw_compact = text.replace(" ", "").replace("　", "")
    for token, cargo in CARGO_ALIASES.items():
        token_l = token.lower()
        if token_l in lowered or token_l in compact or token in text or token in raw_compact:
            return cargo
    return None


def _confirmation_reasons(candidate: Dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if candidate.get("intent_type") != "delivery":
        return reasons
    if not candidate.get("site"):
        reasons.append("site_not_clear")
    if not candidate.get("cargo_type"):
        reasons.append("cargo_type_not_clear")
    if candidate.get("x") is None or candidate.get("y") is None:
        reasons.append("coordinates_not_available")
    return reasons
    
    
def _fallback_parse(text: str, requested_by: str) -> Dict[str, Any]:
    # 本地规则解析只在明确识别到区域/物资时才自动放行；
    # 否则交给安全闸门返回 need_confirmation，避免默认猜成 zone_a/supply。
    site = _explicit_site_from_text(text)
    cargo_type = _explicit_cargo_from_text(text)

    x = None
    y = None
    if site in SITE_MAP:
        x, y = SITE_MAP[site]

    candidate = {
        "task_id": f"nl_{next(_counter):03d}",
        "intent_type": "delivery",
        "site": site,
        "x": x,
        "y": y,
        "priority": infer_priority(text),
        "cargo_type": cargo_type,
        "note": text.strip(),
        "requested_by": requested_by,
        "source": "fallback_rule",
        "control_action": None,
        "target_robot": None,
    }

    confirmation_reasons = _confirmation_reasons(candidate)
    candidate["needs_confirmation"] = bool(confirmation_reasons)
    candidate["confirmation_reasons"] = confirmation_reasons
    return candidate


def _extract_json_text(content: str) -> str:
    cleaned = content.strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.replace("```json", "").replace("```", "").strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and start < end:
        cleaned = cleaned[start:end + 1]

    return cleaned


def _normalize_candidate(data: Dict[str, Any], text: str, requested_by: str) -> Dict[str, Any]:
    intent_type = str(data.get("intent_type", "unknown")).strip().lower()
    if intent_type not in ALLOWED_INTENTS:
        intent_type = "unknown"

    site = data.get("site")
    if site not in ALLOWED_SITES:
    # 不再默认猜成 zone_a；如果文本没有明确区域，则交给 need_confirmation。
    	site = _explicit_site_from_text(text) if intent_type == "delivery" else None

    cargo_type = data.get("cargo_type")
    if cargo_type not in ALLOWED_CARGO:
    # 不再默认猜成 supply；如果文本没有明确物资，则交给 need_confirmation。
   	 cargo_type = _explicit_cargo_from_text(text) if intent_type == "delivery" else None

    try:
        priority = int(data.get("priority", infer_priority(text)))
    except Exception:
        priority = infer_priority(text)

    priority = max(1, min(priority, 5))

    control_action = data.get("control_action")
    if control_action is not None:
        control_action = str(control_action).strip() or None

    target_robot = data.get("target_robot")
    if target_robot is not None:
        target_robot = str(target_robot).strip() or None

    x = None
    y = None
    if intent_type == "delivery" and site in SITE_MAP:
        x, y = SITE_MAP[site]

    candidate = {
        "task_id": f"nl_{next(_counter):03d}",
        "intent_type": intent_type,
        "site": site,
        "x": x,
        "y": y,
        "priority": priority,
        "cargo_type": cargo_type,
        "note": text.strip(),
        "requested_by": requested_by,
        "source": "qwen_api",
        "control_action": control_action,
        "target_robot": target_robot,
	}

    confirmation_reasons = _confirmation_reasons(candidate)
    candidate["needs_confirmation"] = bool(confirmation_reasons)
    candidate["confirmation_reasons"] = confirmation_reasons
    return candidate

async def parse_task_via_qwen(text: str, requested_by: str) -> Dict[str, Any]:
    # 兼容最新版系统的 AI_* 配置，也兼容旧版 DASHSCOPE_* 配置。
    # 使用阿里云百炼 / DashScope 时，AI_PROVIDER=openai 表示走 OpenAI 兼容接口。
    api_key = (
        os.getenv("AI_API_KEY", "")
        or os.getenv("DASHSCOPE_API_KEY", "")
    ).strip()
    api_base = (
        os.getenv("AI_BASE_URL", "")
        or os.getenv("DASHSCOPE_BASE_URL", "")
        or "https://dashscope.aliyuncs.com/compatible-mode/v1"
    ).rstrip("/")
    model = (
        os.getenv("AI_MODEL", "")
        or os.getenv("DASHSCOPE_MODEL", "")
        or "qwen-plus"
    ).strip()

    print("\n[QWEN] ===== new request =====", flush=True)
    print("[QWEN] input text:", repr(text), flush=True)
    print("[QWEN] requested_by:", requested_by, flush=True)
    print("[QWEN] api_base:", api_base, flush=True)
    print("[QWEN] model:", model, flush=True)
    print("[QWEN] api_key_exists:", bool(api_key), flush=True)

    if not text.strip():
        raise ValueError("empty_text")

    if not api_key:
        print("[QWEN] no api key found, fallback to local rule parser", flush=True)
        return _fallback_parse(text, requested_by)

    system_prompt = """
你是机器人安全任务网关前面的语义解析器。
你的职责不是下发命令，而是把用户自然语言归一化成候选 JSON。

你只能输出 JSON，不能输出解释、代码块、markdown。

请将输入识别为以下三类之一：
1. delivery：普通配送/投送/运送/送达类任务
2. control：暂停机器人、下线机器人、恢复证书、吊销证书、修改安全策略、清空任务等控制/管理类意图
3. unknown：意图模糊、无法安全判断、不是系统支持的任务

输出字段规则：
- intent_type: 只能是 delivery / control / unknown
- site: 只能是 zone_a / zone_b / zone_c / zone_d / dock / null
- priority: 1~5 的整数；如果不是 delivery，可填 null
- cargo_type: 只能是 medical / food / supply / repair / document / battery / null
- control_action: 若是 control，则填写简短动作名；否则为 null
- target_robot: 若文本明确指定某只机器狗，如 dog1，则填写；否则为 null

注意：
- “地区2”“二区”“二号区域”“B区”这类表达，如能判断，请统一归一化成 zone_b
- “让狗1停一下”“先别动”“暂停dog1”“让1号机器人休眠”这类表达，都属于 control
- “禁区”“禁止区域”“forbidden_area”这类目标，如果用户要求直接进入，应识别为高风险，不要硬归一化成合法配送区域
- “绕过安全策略”“不要经过安全检查”“绕过认证”“直接执行控制命令”等表达，应识别为 control
- 如果不确定，宁可输出 unknown，也不要硬猜 delivery

delivery 示例：
{"intent_type":"delivery","site":"zone_b","priority":5,"cargo_type":"medical","control_action":null,"target_robot":null}

control 示例：
{"intent_type":"control","site":null,"priority":null,"cargo_type":null,"control_action":"pause_robot","target_robot":"dog1"}

unknown 示例：
{"intent_type":"unknown","site":null,"priority":null,"cargo_type":null,"control_action":null,"target_robot":null}
""".strip()

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text.strip()},
        ],
        "temperature": 0,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    print("[QWEN] about to call remote API...", flush=True)
    print("[QWEN] request url:", f"{api_base}/chat/completions", flush=True)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{api_base}/chat/completions",
                headers=headers,
                json=payload,
            )

        print("[QWEN] response status:", resp.status_code, flush=True)
        print("[QWEN] response text:", resp.text, flush=True)

        resp.raise_for_status()
        result = resp.json()

        content = result["choices"][0]["message"]["content"]
        print("[QWEN] raw model content:", repr(content), flush=True)

        cleaned = _extract_json_text(content)
        print("[QWEN] cleaned content:", repr(cleaned), flush=True)

        data = json.loads(cleaned)
        print("[QWEN] parsed json:", data, flush=True)

        normalized = _normalize_candidate(data, text, requested_by)
        print("[QWEN] normalized candidate:", normalized, flush=True)
        print("[QWEN] using remote qwen result", flush=True)

        return normalized

    except Exception as e:
        print("[QWEN] exception occurred:", repr(e), flush=True)
        print("[QWEN] fallback to local rule parser", flush=True)
        fallback = _fallback_parse(text, requested_by)
        print("[QWEN] fallback candidate:", fallback, flush=True)
        return fallback

# -----------------------------------------------------------------------------
# PlanIR parser for long / compound natural-language tasks
# -----------------------------------------------------------------------------

def _new_plan_id() -> str:
    return f"plan_{next(_counter):03d}"


def _looks_like_if_then_text(text: str) -> bool:
    """识别“如果/若/一旦/当……则/就……”等条件型表达。

    当前比赛版本不自动执行条件分支；检测到后会降级为 need_confirmation。
    """
    compact = text.replace(" ", "").replace("　", "")
    if not compact:
        return False
    starters = ["如果", "若", "假如", "一旦", "当"]
    followers = ["则", "就", "那么"]
    return any(w in compact for w in starters) and any(w in compact for w in followers)


def _action_part_after_if_then(text: str) -> str:
    """提取条件句后半段动作，用于提示/表单预填，不用于自动执行。"""
    import re

    parts = re.split(r"(?:则|那么|就)", text, maxsplit=1)
    if len(parts) == 2 and parts[1].strip():
        return parts[1].strip(" ，,。；;")
    return text.strip()


def _unsupported_if_then_single_task(text: str, requested_by: str) -> Dict[str, Any]:
    """条件型自然语言任务不进入自动执行链路，而是转人工确认。"""
    action_text = _action_part_after_if_then(text)
    candidate = _fallback_parse(action_text, requested_by)
    candidate["note"] = text.strip()
    candidate["source"] = "if_then_requires_operator_confirmation"
    reasons = list(candidate.get("confirmation_reasons") or [])
    if "unsupported_if_then_task" not in reasons:
        reasons.insert(0, "unsupported_if_then_task")
    candidate["needs_confirmation"] = True
    candidate["confirmation_reasons"] = reasons
    return {
        "ir_type": "single_task",
        "plan_id": _new_plan_id(),
        "mode": "single",
        "raw_text": text.strip(),
        "requested_by": requested_by,
        "requires_confirmation": True,
        "single_task": candidate,
        "steps": [],
        "source": "if_then_not_auto_executed",
    }


def _step_from_fragment(fragment: str, step_id: str, requested_by: str, *, assignee: dict | None = None, depends_on: list[str] | None = None) -> Dict[str, Any]:
    fragment = fragment.strip(" ，,。；;先再然后同时分别并且和") or fragment.strip()
    site = _explicit_site_from_text(fragment)
    cargo_type = _explicit_cargo_from_text(fragment)
    confirmation_reasons: list[str] = []
    if not cargo_type:
        # 旧版 Task 只能承载 delivery 类字段；对“去A区/巡检A区”这类到达类表达，
        # 用 supply 作为兼容占位，同时强制计划确认，避免静默猜测。
        cargo_type = "supply"
        confirmation_reasons.append("cargo_defaulted_to_supply")

    x = y = None
    if site in SITE_MAP:
        x, y = SITE_MAP[site]
    else:
        confirmation_reasons.append("site_not_clear")

    return {
        "step_id": step_id,
        "intent_type": "delivery",
        "site": site,
        "x": x,
        "y": y,
        "priority": infer_priority(fragment),
        "cargo_type": cargo_type,
        "note": fragment,
        "assignee": assignee or {"type": "auto"},
        "depends_on": depends_on or [],
        "confirmation_reasons": confirmation_reasons,
    }


def _extract_site_fragments(text: str) -> list[str]:
    """把长句粗略切成含区域信息的片段，供无 API_KEY 时本地演示。"""
    import re

    normalized = text.strip()
    pieces = re.split(r"(?:，|,|。|；|;|然后|再让|再派|再叫|再|同时|分别|并且|和)", normalized)
    fragments = []
    for p in pieces:
        p = p.strip()
        if not p:
            continue
        if _explicit_site_from_text(p) or _explicit_cargo_from_text(p):
            fragments.append(p)
    return fragments


def _guess_plan_mode(text: str, step_count: int) -> str:
    if step_count <= 1:
        return "single"
    # “同时/分别/另一条/再让一条狗”明确表达多个执行体，按并行处理。
    if any(w in text for w in ["同时", "分别", "各派", "各让", "另一条", "另一台", "再让一条", "再派一条"]):
        return "parallel"
    # “同一条/先...再/随后/接着/然后”表达同一执行体或先后依赖，按顺序处理。
    if any(w in text for w in ["同一条", "同一台", "先", "随后", "接着", "然后"]):
        return "sequential"
    return "parallel"


def _fallback_parse_plan(text: str, requested_by: str) -> Dict[str, Any]:
    plan_id = _new_plan_id()

    if _looks_like_if_then_text(text):
        return _unsupported_if_then_single_task(text, requested_by)

    fragments = _extract_site_fragments(text)
    if len(fragments) <= 1:
        candidate = _fallback_parse(text, requested_by)
        return {
            "ir_type": "single_task",
            "plan_id": plan_id,
            "mode": "single",
            "raw_text": text.strip(),
            "requested_by": requested_by,
            "requires_confirmation": bool(candidate.get("needs_confirmation")),
            "single_task": candidate,
            "steps": [_step_from_fragment(text, "s1", requested_by)],
            "source": "fallback_plan_rule",
        }

    mode = _guess_plan_mode(text, len(fragments))
    steps: list[Dict[str, Any]] = []
    previous_step_id = None
    for idx, fragment in enumerate(fragments, start=1):
        sid = f"s{idx}"
        depends_on: list[str] = []
        assignee: Dict[str, Any] = {"type": "auto"}
        if mode == "sequential" and previous_step_id:
            depends_on = [previous_step_id]
            assignee = {"type": "same_as", "same_as_step": previous_step_id}
        elif mode == "parallel":
            assignee = {"type": "auto", "distinct_group": plan_id}
        step = _step_from_fragment(fragment, sid, requested_by, assignee=assignee, depends_on=depends_on)
        steps.append(step)
        previous_step_id = sid

    return {
        "ir_type": "plan",
        "plan_id": plan_id,
        "mode": mode,
        "raw_text": text.strip(),
        "requested_by": requested_by,
        "requires_confirmation": True,
        "steps": steps,
        "source": "fallback_plan_rule",
    }


def _normalize_plan_ir(data: Dict[str, Any], text: str, requested_by: str) -> Dict[str, Any]:
    """把远程模型输出的 PlanIR 归一化，防止字段缺失/越界。"""
    if not isinstance(data, dict):
        return _fallback_parse_plan(text, requested_by)

    if _looks_like_if_then_text(text):
        return _unsupported_if_then_single_task(text, requested_by)

    mode = str(data.get("mode", "single")).strip().lower()
    if mode not in {"single", "parallel", "sequential"}:
        mode = "single"

    # 对远程模型输出做一次保守纠偏：中文里“同时/分别/另一条/再让一条狗”表示多个执行体；
    # “先……再……”或“同一条机器狗”才是顺序计划。
    if any(w in text for w in ["同时", "分别", "各派", "各让", "另一条狗", "另一台", "再让一条狗", "再派一条狗"]):
        mode = "parallel"
    elif any(w in text for w in ["同一条", "同一台", "先", "随后", "接着", "然后"]):
        mode = "sequential"

    steps_in = data.get("steps") or []
    if not isinstance(steps_in, list) or not steps_in:
        if "single_task" in data and isinstance(data["single_task"], dict):
            candidate = _normalize_candidate(data["single_task"], text, requested_by)
        else:
            candidate = _normalize_candidate(data, text, requested_by)
        return {
            "ir_type": "single_task",
            "plan_id": data.get("plan_id") or _new_plan_id(),
            "mode": "single",
            "raw_text": text.strip(),
            "requested_by": requested_by,
            "requires_confirmation": bool(candidate.get("needs_confirmation")),
            "single_task": candidate,
            "steps": [_step_from_fragment(text, "s1", requested_by)],
            "source": "qwen_plan_api",
        }

    normalized_steps: list[Dict[str, Any]] = []
    for idx, raw_step in enumerate(steps_in, start=1):
        if not isinstance(raw_step, dict):
            continue
        sid = str(raw_step.get("step_id") or f"s{idx}")
        fragment = str(raw_step.get("note") or raw_step.get("evidence", {}).get("text_span") or text)
        step = _step_from_fragment(fragment, sid, requested_by)

        intent_type = str(raw_step.get("intent_type") or raw_step.get("intent") or step["intent_type"]).lower()
        if intent_type not in ALLOWED_INTENTS:
            intent_type = "unknown"
        step["intent_type"] = intent_type

        site = raw_step.get("site")
        if site in ALLOWED_SITES:
            step["site"] = site
            step["x"], step["y"] = SITE_MAP[site]
        cargo_type = raw_step.get("cargo_type")
        if cargo_type in ALLOWED_CARGO:
            step["cargo_type"] = cargo_type
            if "cargo_defaulted_to_supply" in step["confirmation_reasons"]:
                step["confirmation_reasons"].remove("cargo_defaulted_to_supply")
        try:
            step["priority"] = max(1, min(int(raw_step.get("priority", step["priority"])), 5))
        except Exception:
            step["priority"] = max(1, min(step["priority"], 5))

        assignee = raw_step.get("assignee")
        if isinstance(assignee, dict) and assignee.get("type") in {"auto", "same_as", "explicit"}:
            step["assignee"] = assignee
        elif mode == "parallel":
            step["assignee"] = {"type": "auto", "distinct_group": data.get("plan_id") or "plan_group"}
        elif mode == "sequential" and idx > 1:
            step["assignee"] = {"type": "same_as", "same_as_step": f"s{idx-1}"}

        depends_on = raw_step.get("depends_on")
        if isinstance(depends_on, list):
            step["depends_on"] = [str(x) for x in depends_on]
        elif mode == "sequential" and idx > 1:
            step["depends_on"] = [f"s{idx-1}"]
        normalized_steps.append(step)

    if len(normalized_steps) <= 1 and mode == "single":
        candidate = _normalize_candidate(data.get("single_task", data), text, requested_by)
        return {
            "ir_type": "single_task",
            "plan_id": data.get("plan_id") or _new_plan_id(),
            "mode": "single",
            "raw_text": text.strip(),
            "requested_by": requested_by,
            "requires_confirmation": bool(candidate.get("needs_confirmation")),
            "single_task": candidate,
            "steps": normalized_steps or [_step_from_fragment(text, "s1", requested_by)],
            "source": "qwen_plan_api",
        }

    return {
        "ir_type": "plan",
        "plan_id": data.get("plan_id") or _new_plan_id(),
        "mode": mode if len(normalized_steps) > 1 else "single",
        "raw_text": text.strip(),
        "requested_by": requested_by,
        "requires_confirmation": True if len(normalized_steps) > 1 or mode in {"parallel", "sequential"} else bool(data.get("requires_confirmation")),
        "steps": normalized_steps,
        "source": "qwen_plan_api",
    }


async def parse_plan_via_qwen(text: str, requested_by: str) -> Dict[str, Any]:
    """把自然语言解析为 SingleTask 或 PlanIR。

    没有 AI_API_KEY/DASHSCOPE_API_KEY 时，自动走本地规则解析，方便比赛现场演示和测试。
    """
    api_key = (
        os.getenv("AI_API_KEY", "")
        or os.getenv("DASHSCOPE_API_KEY", "")
    ).strip()
    api_base = (
        os.getenv("AI_BASE_URL", "")
        or os.getenv("DASHSCOPE_BASE_URL", "")
        or "https://dashscope.aliyuncs.com/compatible-mode/v1"
    ).rstrip("/")
    model = (
        os.getenv("AI_MODEL", "")
        or os.getenv("DASHSCOPE_MODEL", "")
        or "qwen-plus"
    ).strip()

    if not text.strip():
        raise ValueError("empty_text")

    if not api_key:
        return _fallback_parse_plan(text, requested_by)

    system_prompt = """
你是机器狗集群安全系统的 PlanIR 解析器。
你的职责只是把用户自然语言解析为 JSON 计划，不拥有最终执行权。
你只能输出 JSON，不能输出解释、markdown 或代码块。

请输出以下格式之一：

单任务：
{
  "ir_type": "single_task",
  "mode": "single",
  "requires_confirmation": false,
  "single_task": {
    "intent_type": "delivery",
    "site": "zone_a|zone_b|zone_c|zone_d|dock|null",
    "priority": 1,
    "cargo_type": "medical|food|supply|repair|document|battery|null",
    "control_action": null,
    "target_robot": null
  },
  "steps": []
}

多步骤计划：
{
  "ir_type": "plan",
  "mode": "parallel|sequential",
  "requires_confirmation": true,
  "steps": [
    {
      "step_id": "s1",
      "intent_type": "delivery",
      "site": "zone_a|zone_b|zone_c|zone_d|dock|null",
      "priority": 1,
      "cargo_type": "medical|food|supply|repair|document|battery|null",
      "note": "原文中对应片段",
      "assignee": {"type": "auto"},
      "depends_on": []
    }
  ]
}

规则：
- 当前版本只支持 single、parallel、sequential 三类任务。
- “先……再……/然后……”通常是 sequential。
- “同时/分别/各派/另一条机器狗/让一条狗去A，再让一条狗去B”通常是 parallel。
- “如果/若/一旦/当……就/则……”等条件触发任务不自动执行；仍输出 single_task，site/cargo 尽量按后半句动作识别，requires_confirmation 填 true。
- 普通用户明确指定 dog1/dog2 时，assignee.type 写 explicit，并填 robot_id；后续安全闸门会拦截。
- 不支持 control 类自然语言任务；出现关闭安全、绕过审计、禁区、吊销证书等，仍如实放入字段或 note，不要伪装为安全任务。
- 如果不确定区域或物资，填 null，不要硬猜。
""".strip()

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text.strip()},
        ],
        "temperature": 0,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{api_base}/chat/completions",
                headers=headers,
                json=payload,
            )
        resp.raise_for_status()
        result = resp.json()
        content = result["choices"][0]["message"]["content"]
        cleaned = _extract_json_text(content)
        data = json.loads(cleaned)
        return _normalize_plan_ir(data, text, requested_by)
    except Exception as e:
        print("[PLAN_QWEN] fallback to local PlanIR parser:", repr(e), flush=True)
        return _fallback_parse_plan(text, requested_by)
