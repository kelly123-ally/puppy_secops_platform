from __future__ import annotations

from pathlib import Path

from .core.qwen_client import parse_task_via_qwen, parse_plan_via_qwen
from .core.task_guard import validate_task_candidate
from .core.plan_guard import validate_plan_ir

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .auth import SessionStore, authenticate, require_roles, require_user
from .main import get_hub, get_simulator

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    session_token = request.cookies.get("session_token")
    store: SessionStore = request.app.state.sessions
    if store.get(session_token):
        return RedirectResponse(url="/app", status_code=302)
    return templates.TemplateResponse(request=request, name="login.html", context={})


@router.get("/app", response_class=HTMLResponse)
async def app_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"user": None},
    )


@router.post("/api/login")
async def api_login(request: Request, payload: dict = Body(...)) -> Response:
    username = authenticate(payload.get("username", ""), payload.get("password", ""))
    if not username:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    token = request.app.state.sessions.create(username)
    info = request.app.state.sessions.get(token)
    resp = JSONResponse({"ok": True, "token": token, "user": {"username": info.username, "role": info.role, "display_name": info.display_name}})
    resp.set_cookie("session_token", token, httponly=True, samesite="lax", max_age=60 * 60 * 8)
    return resp


@router.post("/api/logout")
async def api_logout(request: Request) -> Response:
    token = request.cookies.get("session_token")
    request.app.state.sessions.destroy(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session_token")
    return resp


@router.get("/api/bootstrap")
async def api_bootstrap(request: Request):
    user = require_user(request)
    simulator = get_simulator(request.app)
    return simulator.bootstrap({"username": user.username, "role": user.role, "display_name": user.display_name})


@router.get("/api/state")
async def api_state(request: Request):
    require_user(request)
    simulator = get_simulator(request.app)
    return simulator.snapshot()


@router.get("/api/audit")
async def api_audit(request: Request):
    require_roles(request, {"admin", "auditor", "operator"})
    simulator = get_simulator(request.app)
    return {"items": simulator.snapshot()["audit"]}


@router.post("/api/tasks/natural")
async def api_natural_task(request: Request, payload: dict = Body(...)):
    user = require_roles(request, {"admin", "operator"})
    simulator = get_simulator(request.app)

    text = payload.get("text", "").strip()
    plan_ir = await parse_plan_via_qwen(text, requested_by=user.username)

    # 兼容旧单任务路径：PlanIR 判断为 single_task 时，仍走原 TaskGuard + submit_signed_task。
    if plan_ir.get("ir_type") == "single_task":
        candidate = plan_ir.get("single_task") or await parse_task_via_qwen(text, requested_by=user.username)
        guard_result = validate_task_candidate(candidate, raw_text=text, username=user.username)

        print("\n[GUARD] ===== single task security check =====", flush=True)
        print("[GUARD] raw_text:", repr(text), flush=True)
        print("[GUARD] decision:", guard_result["decision"], flush=True)
        print("[GUARD] reasons:", guard_result["reasons"], flush=True)

        simulator.log(
            "info" if guard_result["decision"] == "allow" else "warn",
            "guard",
            "nl_candidate_checked",
            {
                "raw_text": text,
                "decision": guard_result["decision"],
                "risk_level": guard_result["risk_level"],
                "reasons": guard_result["reasons"],
                "candidate": guard_result["audit_candidate"],
            },
        )

        if guard_result["decision"] == "block":
            return {
                "ok": False,
                "stage": "task_guard",
                "message": "任务被安全策略阻断",
                "risk_level": guard_result["risk_level"],
                "reasons": guard_result["reasons"],
                "task_candidate": guard_result["audit_candidate"],
            }

        if guard_result["decision"] == "need_confirmation":
            reasons = guard_result["reasons"]
            if "unsupported_if_then_task" in reasons:
                message = "检测到条件型任务表达。当前版本不自动创建条件分支，请根据实时状态回传确认异常后再下发具体任务。"
            else:
                message = "任务信息不完整或不够明确，请确认或补全目标区域、物资类型等字段后再提交。"
            return {
                "ok": False,
                "stage": "need_confirmation",
                "message": message,
                "risk_level": guard_result["risk_level"],
                "reasons": reasons,
                "task_candidate": guard_result["audit_candidate"],
                "fill_suggestion": guard_result["audit_candidate"],
            }

        final_task = guard_result["final_task"]
        simulator.log(
            "info",
            "guard",
            "nl_task_allowed",
            {"raw_text": text, "final_task": final_task, "candidate": guard_result["audit_candidate"]},
        )
        return simulator.submit_signed_task(final_task, actor=user.username, source=final_task.get("source", "qwen_api"))

    # 新长难句路径：先做计划级审查。安全但复杂的计划必须经确认后才会编译为子任务。
    plan_guard = validate_plan_ir(plan_ir, raw_text=text, username=user.username)
    print("\n[PLAN_GUARD] ===== plan security check =====", flush=True)
    print("[PLAN_GUARD] raw_text:", repr(text), flush=True)
    print("[PLAN_GUARD] mode:", plan_ir.get("mode"), flush=True)
    print("[PLAN_GUARD] decision:", plan_guard["decision"], flush=True)
    print("[PLAN_GUARD] reasons:", plan_guard["reasons"], flush=True)

    simulator.log(
        "info" if plan_guard["decision"] == "allow" else "warn",
        "plan_guard",
        "plan_candidate_checked",
        {
            "raw_text": text,
            "plan_id": plan_ir.get("plan_id"),
            "mode": plan_ir.get("mode"),
            "decision": plan_guard["decision"],
            "risk_level": plan_guard["risk_level"],
            "reasons": plan_guard["reasons"],
            "step_results": plan_guard["step_results"],
        },
    )

    if plan_guard["decision"] == "block":
        return {
            "ok": False,
            "stage": "plan_guard",
            "message": "长难句计划被安全策略阻断",
            "risk_level": plan_guard["risk_level"],
            "reasons": plan_guard["reasons"],
            "plan_candidate": plan_ir,
            "step_results": plan_guard["step_results"],
        }

    if plan_guard["decision"] == "need_confirmation":
        return simulator.store_pending_plan(plan_ir, plan_guard, actor=user.username)

    # 理论上只会出现在 single 或非常简单安全计划；保留自动执行能力。
    pending = simulator.store_pending_plan(plan_ir, plan_guard, actor=user.username)
    return simulator.confirm_plan(pending["plan_id"], actor=user.username)


@router.post("/api/plans/confirm")
async def api_confirm_plan(request: Request, payload: dict = Body(...)):
    user = require_roles(request, {"admin", "operator"})
    simulator = get_simulator(request.app)
    return simulator.confirm_plan(str(payload.get("plan_id", "")), actor=user.username)


@router.post("/api/plans/cancel")
async def api_cancel_plan(request: Request, payload: dict = Body(...)):
    user = require_roles(request, {"admin", "operator"})
    simulator = get_simulator(request.app)
    return simulator.cancel_pending_plan(str(payload.get("plan_id", "")), actor=user.username)


@router.post("/api/tasks/structured")
async def api_structured_task(request: Request, payload: dict = Body(...)):
    user = require_roles(request, {"admin", "operator"})
    simulator = get_simulator(request.app)
    task = simulator.build_demo_task(
        site=payload.get("site", "zone_a"),
        cargo_type=payload.get("cargo_type", "supply"),
        priority=int(payload.get("priority", 3)),
        note=payload.get("note", ""),
        actor=user.username,
    )
    return simulator.submit_signed_task(task, actor=user.username)


@router.post("/api/policies/update")
async def api_update_policy(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin"})
    simulator = get_simulator(request.app)
    return simulator.toggle_policy(payload["name"], payload["value"])


@router.post("/api/robots/pause")
async def api_pause_robot(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "operator"})
    simulator = get_simulator(request.app)
    return simulator.set_robot_pause(payload["robot_id"], bool(payload["paused"]))


@router.post("/api/robots/offline")
async def api_offline_robot(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "operator"})
    simulator = get_simulator(request.app)
    return simulator.set_robot_offline(payload["robot_id"], bool(payload["offline"]))


@router.post("/api/robots/recover")
async def api_recover_robot(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin"})
    simulator = get_simulator(request.app)
    return simulator.recover_robot(payload["robot_id"])


@router.post("/api/attacks/unsigned_injection")
async def api_attack_unsigned(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "auditor"})
    simulator = get_simulator(request.app)
    task = simulator.build_demo_task(
        site=payload.get("site", "zone_b"),
        cargo_type=payload.get("cargo_type", "supply"),
        priority=int(payload.get("priority", 5)),
        note="未经签名注入攻击",
        task_id=f"atk_{payload.get('site', 'b')}_{int(__import__('time').time())}",
        actor="attack_lab",
    )
    return simulator.attack_unsigned_injection(task)


@router.post("/api/attacks/replay")
async def api_attack_replay(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "auditor"})
    simulator = get_simulator(request.app)
    task = simulator.build_demo_task(
        site=payload.get("site", "zone_c"),
        cargo_type="supply",
        priority=4,
        note="重放攻击测试",
        task_id=f"replay_{int(__import__('time').time())}",
        actor="attack_lab",
    )
    return simulator.attack_replay(task)


@router.post("/api/attacks/heartbeat_spoof")
async def api_attack_spoof(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "auditor"})
    simulator = get_simulator(request.app)
    return simulator.attack_heartbeat_spoof(payload["robot_id"])


@router.post("/api/attacks/compromise")
async def api_attack_compromise(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "auditor"})
    simulator = get_simulator(request.app)
    return simulator.compromise_robot(payload["robot_id"])


@router.post("/api/attacks/mitm")
async def api_attack_mitm(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "auditor"})
    simulator = get_simulator(request.app)
    return simulator.attack_mitm(
        robot_id=payload.get("robot_id", "dog1"),
        target_site=payload.get("site", "zone_b")
    )


@router.post("/api/attacks/ddos")
async def api_attack_ddos(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "auditor"})
    simulator = get_simulator(request.app)
    return simulator.attack_ddos(
        target=payload.get("target", "control_center"),
        intensity=payload.get("intensity", "medium")
    )


@router.post("/api/attacks/privilege_escalation")
async def api_attack_privilege_escalation(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "auditor"})
    simulator = get_simulator(request.app)
    return simulator.attack_privilege_escalation(
        robot_id=payload.get("robot_id", "dog1"),
        target_role=payload.get("target_role", "admin")
    )


@router.post("/api/attacks/cert_forge")
async def api_attack_cert_forge(request: Request, payload: dict = Body(...)):
    require_roles(request, {"admin", "auditor"})
    simulator = get_simulator(request.app)
    return simulator.attack_cert_forge(
        robot_id=payload.get("robot_id", "dog1")
    )


@router.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket):
    token = websocket.query_params.get("token") or websocket.cookies.get("session_token")
    store: SessionStore = websocket.app.state.sessions
    user = store.get(token)
    if not user:
        await websocket.close(code=4401)
        return
    hub = get_hub(websocket.app)
    await hub.connect(websocket)
    simulator = get_simulator(websocket.app)
    try:
        await websocket.send_json(simulator.bootstrap({"username": user.username, "role": user.role, "display_name": user.display_name}))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(websocket)

@router.post("/api/tasks/cancel")
async def api_cancel_task(request: Request, payload: dict = Body(...)):
    user = require_roles(request, {"admin", "operator"})
    simulator = get_simulator(request.app)
    return simulator.control_cancel_task(
        task_id=payload["task_id"],
        actor=user.username,
        reason=payload.get("reason", "operator_cancel"),
    )


@router.post("/api/robots/revoke")
async def api_revoke_robot(request: Request, payload: dict = Body(...)):
    user = require_roles(request, {"admin"})
    simulator = get_simulator(request.app)
    return simulator.control_revoke_robot(
        robot_id=payload["robot_id"],
        actor=user.username,
        reason=payload.get("reason", "manual_revoke"),
    )
