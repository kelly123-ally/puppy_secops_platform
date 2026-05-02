from __future__ import annotations

import itertools
import re
from typing import Dict, Tuple


SITE_MAP: Dict[str, Tuple[int, int]] = {
    "zone_a": (5, 4),
    "zone_b": (24, 4),
    "zone_c": (8, 14),
    "zone_d": (24, 14),
    "dock": (2, 2),
}

_counter = itertools.count(1)


def infer_site(text: str) -> str:
    lowered = text.lower()
    mapping = {
        "a区": "zone_a",
        "a区域": "zone_a",
        "zone_a": "zone_a",
        "b区": "zone_b",
        "b区域": "zone_b",
        "zone_b": "zone_b",
        "c区": "zone_c",
        "c区域": "zone_c",
        "zone_c": "zone_c",
        "d区": "zone_d",
        "d区域": "zone_d",
        "zone_d": "zone_d",
        "充电": "dock",
        "回充": "dock",
        "dock": "dock",
    }
    for key, value in mapping.items():
        if key in lowered or key in text:
            return value
    return "zone_a"


def infer_priority(text: str) -> int:
    if any(k in text for k in ["最高", "紧急", "立即", "急需", "高优先"]):
        return 5
    if any(k in text for k in ["高", "尽快", "优先"]):
        return 4
    if any(k in text for k in ["中", "一般"]):
        return 3
    if any(k in text for k in ["低", "不急"]):
        return 2
    return 3


def infer_cargo(text: str) -> str:
    checks = [
        ("药", "medical"),
        ("医疗", "medical"),
        ("急救", "medical"),
        ("食物", "food"),
        ("补给", "supply"),
        ("维修", "repair"),
        ("工具", "repair"),
        ("文档", "document"),
        ("电池", "battery"),
    ]
    for token, cargo in checks:
        if token in text:
            return cargo
    return "supply"


def parse_natural_task(text: str, requested_by: str = "operator") -> dict:
    site = infer_site(text)
    x, y = SITE_MAP[site]
    return {
        "task_id": f"nl_{next(_counter):03d}",
        "site": site,
        "x": x,
        "y": y,
        "priority": infer_priority(text),
        "cargo_type": infer_cargo(text),
        "note": text.strip(),
        "requested_by": requested_by,
        "source": "nl_agent",
    }
