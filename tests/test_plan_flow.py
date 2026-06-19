"""Smoke tests for PlanIR long-command support.

Run from project root:
    PYTHONPATH=. python tests/test_plan_flow.py
"""
from __future__ import annotations

import asyncio
import os

from app.core.qwen_client import parse_plan_via_qwen
from app.core.plan_guard import validate_plan_ir
from app.core.simulator import FleetSimulator


async def parse_and_confirm(text: str):
    os.environ.pop("AI_API_KEY", None)
    os.environ.pop("DASHSCOPE_API_KEY", None)
    plan = await parse_plan_via_qwen(text, "alice")
    guard = validate_plan_ir(plan, raw_text=text, username="alice")
    sim = FleetSimulator()
    pending = sim.store_pending_plan(plan, guard, actor="alice")
    assert pending["stage"] == "plan_need_confirmation"
    confirmed = sim.confirm_plan(pending["plan_id"], actor="alice")
    assert confirmed["ok"] is True
    return plan, sim


async def test_single_allow():
    os.environ.pop("AI_API_KEY", None)
    os.environ.pop("DASHSCOPE_API_KEY", None)
    plan = await parse_plan_via_qwen("去B区送急救包", "alice")
    assert plan["ir_type"] == "single_task"
    assert plan["single_task"]["site"] == "zone_b"
    assert plan["single_task"]["cargo_type"] == "medical"


async def test_parallel():
    plan, sim = await parse_and_confirm("同时派一条机器狗去A区送文件，并派另一条机器狗去B区送急救包")
    assert plan["mode"] == "parallel"
    assert len(sim.tasks) == 2
    assert all(t.lease_id for t in sim.tasks.values())


async def test_sequential_same_robot():
    plan, sim = await parse_and_confirm("派同一条机器狗先去A区送文件，再去B区送急救包")
    assert plan["mode"] == "sequential"
    # 初始只启动第一步
    assert len(sim.tasks) == 1
    for _ in range(120):
        sim.tick()
        if sim.plans[plan["plan_id"]]["status"] == "completed":
            break
    steps = sim.plans[plan["plan_id"]]["steps"]
    assert steps[0]["status"] == "completed"
    assert steps[1]["status"] == "completed"
    assert steps[0]["assigned_robot"] == steps[1]["assigned_robot"]


async def test_if_then_is_not_auto_executed():
    os.environ.pop("AI_API_KEY", None)
    os.environ.pop("DASHSCOPE_API_KEY", None)
    plan = await parse_plan_via_qwen("如果A区巡查发现异常，则派一条机器狗去B区送急救包", "alice")
    assert plan["ir_type"] == "single_task"
    assert plan["single_task"]["needs_confirmation"] is True
    assert "unsupported_if_then_task" in plan["single_task"]["confirmation_reasons"]


async def main():
    await test_single_allow()
    await test_parallel()
    await test_sequential_same_robot()
    await test_if_then_is_not_auto_executed()
    print("PlanIR smoke tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
