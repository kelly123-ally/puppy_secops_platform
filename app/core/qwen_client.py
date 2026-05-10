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
    for token, site in SITE_ALIASES.items():
        if token in lowered or token in text:
            return site
    return None


def _explicit_cargo_from_text(text: str) -> str | None:
    lowered = text.lower()
    for token, cargo in CARGO_ALIASES.items():
        if token in lowered or token in text:
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
