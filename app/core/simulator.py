from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from .lbse import (
    LBSEError,
    LBSEIntegrityError,
    LBSELeaseError,
    LBSENonceReplayError,
    LBSERevokedError,
    LeaseBoundSecureEnvelope,
)
from .models import AuditEvent, PolicySet, Robot, Task
from .nl_agent import SITE_MAP, parse_natural_task
from .planner import GridPlanner


class FleetSimulator:
    """
    这个版本把三类关键消息改造成 LBSE 风格：

    1. AssignTask    control  -> robot
    2. Heartbeat     robot    -> control
    3. CompleteTask  robot    -> control

    同时保留原有 Web 面板接口不变，routes.py 无需大改。
    """

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.width = 32
        self.height = 20
        self.obstacles = self._build_obstacles()
        self.sites = SITE_MAP | {"checkpoint": (15, 10), "dock": (2, 2)}
        self.planner = GridPlanner(self.width, self.height, self.obstacles)
        self.lbse = LeaseBoundSecureEnvelope()

        self.policies = PolicySet()
        self.robots: Dict[str, Robot] = self._build_robots()
        self.tasks: Dict[str, Task] = {}
        # PlanIR support: a long natural-language command becomes one plan,
        # then each executable step is compiled into a normal Task with its own lease.
        self.plans: Dict[str, Dict[str, Any]] = {}
        self.pending_plan_confirmations: Dict[str, Dict[str, Any]] = {}
        self.task_plan_index: Dict[str, Dict[str, str]] = {}

        self.audit_log: Deque[AuditEvent] = deque(maxlen=320)
        self.attack_log: Deque[Dict[str, Any]] = deque(maxlen=80)

        self.assignment_versions: Dict[str, int] = {}
        self.active_assignments: Dict[str, Dict[str, Any]] = {}
        self.completed_leases: set[str] = set()
        self.revoked_certificates: set[str] = set()

        self.security_metrics: Dict[str, int] = {
            "blocked_injections": 0,
            "blocked_replays": 0,
            "blocked_spoofs": 0,
            "blocked_invalid_completions": 0,
            "revoked_robots": 0,
            "successful_attacks": 0,
        }

        self.running = True
        self.last_tick = time.time()
        
        # Anomaly detection integration (Task 21.4)
        self.anomaly_detector = None  # Will be set by application
        self.alert_system = None  # Will be set by application
        self.robot_task_start_times: Dict[str, float] = {}  # Track task start times
        self.robot_message_counts: Dict[str, int] = {}  # Track message frequency
        self.robot_last_message_time: Dict[str, float] = {}  # Track last message time
        
        # Audit logger integration (for Security Dashboard)
        self.audit_logger = None  # Will be set by application

        self._seed_demo_events()

    # -----------------------------
    # 基础初始化
    # -----------------------------
    def _build_obstacles(self) -> List[tuple[int, int]]:
        obstacles: List[tuple[int, int]] = []
        for x in range(10, 22):
            obstacles.append((x, 8))
        for y in range(4, 15):
            obstacles.append((16, y))
        for x in range(4, 9):
            obstacles.append((x, 12))
        for x in range(23, 29):
            obstacles.append((x, 12))
        return obstacles

    def _build_robots(self) -> Dict[str, Robot]:
        now = time.time()
        return {
            "dog1": Robot(robot_id="dog1", x=2, y=2, home=(2, 2), last_heartbeat=now, speed_cells=1),
            "dog2": Robot(robot_id="dog2", x=5, y=2, home=(5, 2), last_heartbeat=now, speed_cells=1),
            "dog3": Robot(robot_id="dog3", x=2, y=5, home=(2, 5), last_heartbeat=now, speed_cells=1),
            "dog4": Robot(robot_id="dog4", x=5, y=5, home=(5, 5), last_heartbeat=now, speed_cells=1),
        }

    def _seed_demo_events(self) -> None:
        self.log("info", "system", "platform_boot", {"message": "LBSE-secured fleet simulator ready"})
        self.log("info", "crypto", "lbse_enabled", {"primitive": "AES-GCM + lease-bound AAD"})
        self.log("info", "policy", "strict_mode_enabled", self.policies.to_dict())

    def log(self, level: str, category: str, title: str, details: Dict[str, Any]) -> None:
        # Log to internal deque for backward compatibility
        self.audit_log.appendleft(AuditEvent(ts=time.time(), level=level, category=category, title=title, details=details))
        
        # Also log to AuditLogger if available (for Security Dashboard)
        if self.audit_logger:
            self.audit_logger.log_event(
                category=category,
                title=title,
                actor=details.get("actor", "system"),
                details=details
            )
    
    def set_anomaly_detector(self, anomaly_detector) -> None:
        """Set anomaly detector for robot behavior monitoring (Task 21.4).
        
        Args:
            anomaly_detector: AnomalyDetector instance
        """
        self.anomaly_detector = anomaly_detector
    
    def set_alert_system(self, alert_system) -> None:
        """Set alert system for generating anomaly alerts (Task 21.4).
        
        Args:
            alert_system: AlertSystem instance
        """
        self.alert_system = alert_system
    
    def set_audit_logger(self, audit_logger) -> None:
        """Set audit logger for centralized audit logging.
        
        Args:
            audit_logger: AuditLogger instance
        """
        self.audit_logger = audit_logger
    
    def _collect_robot_metrics(self, robot: Robot) -> Optional[Any]:
        """Collect behavior metrics for anomaly detection (Task 21.4).
        
        Implements Requirement 17.1: Monitor movement patterns, task completion times,
        battery consumption, and message frequency.
        
        Args:
            robot: Robot to collect metrics from
            
        Returns:
            RobotMetrics object or None if anomaly detector not available
        """
        if not self.anomaly_detector:
            return None
        
        # Import RobotMetrics here to avoid circular dependency
        from .anomaly_detector import RobotMetrics
        
        # Calculate task completion time if task just completed
        task_completion_time = None
        if robot.current_task_id and robot.current_task_id in self.robot_task_start_times:
            task_completion_time = time.time() - self.robot_task_start_times[robot.current_task_id]
        
        # Calculate message frequency (messages per minute)
        now = time.time()
        robot_id = robot.robot_id
        
        # Update message count
        if robot_id not in self.robot_message_counts:
            self.robot_message_counts[robot_id] = 0
            self.robot_last_message_time[robot_id] = now
        
        self.robot_message_counts[robot_id] += 1
        
        # Calculate frequency over last minute
        time_elapsed = now - self.robot_last_message_time[robot_id]
        if time_elapsed >= 60.0:  # Reset every minute
            message_frequency = self.robot_message_counts[robot_id] / (time_elapsed / 60.0)
            self.robot_message_counts[robot_id] = 0
            self.robot_last_message_time[robot_id] = now
        else:
            # Estimate frequency based on current rate
            if time_elapsed > 0:
                message_frequency = self.robot_message_counts[robot_id] / (time_elapsed / 60.0)
            else:
                message_frequency = 0.0
        
        # Calculate movement speed (cells per second)
        # Approximate based on robot's speed_cells attribute
        movement_speed = robot.speed_cells if hasattr(robot, 'speed_cells') else 1.0
        
        # Create metrics object
        metrics = RobotMetrics(
            robot_id=robot_id,
            timestamp=now,
            position=(robot.x, robot.y),
            battery_level=robot.battery,
            task_completion_time=task_completion_time,
            message_frequency=message_frequency,
            movement_speed=movement_speed
        )
        
        return metrics
    
    def _analyze_robot_behavior(self, robot: Robot) -> None:
        """Analyze robot behavior for anomalies and generate alerts (Task 21.4).
        
        Implements Requirements:
        - 17.1: Collect robot behavior metrics
        - 17.3: Generate alerts for detected anomalies
        
        Args:
            robot: Robot to analyze
        """
        if not self.anomaly_detector or not self.alert_system:
            return
        
        # Collect current metrics
        metrics = self._collect_robot_metrics(robot)
        if not metrics:
            return
        
        # Update baseline with current metrics
        self.anomaly_detector.update_baseline(robot.robot_id, metrics)
        
        # Detect anomalies (only if we have sufficient baseline data)
        anomaly_score, anomalous_features, alert_generated = \
            self.anomaly_detector.detect_and_log_anomaly(robot.robot_id, metrics)
        
        # Generate alert if anomaly detected and threshold exceeded
        if alert_generated and anomalous_features:
            # Determine severity based on anomaly score
            if anomaly_score >= 5.0:
                severity = "critical"
            elif anomaly_score >= 4.0:
                severity = "high"
            elif anomaly_score >= 3.0:
                severity = "medium"
            else:
                severity = "low"
            
            # Generate alert asynchronously
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self.alert_system.generate_alert(
                    severity=severity,
                    category="anomaly_critical" if severity == "critical" else "anomaly",
                    subject=robot.robot_id,
                    title=f"Anomalous behavior detected for {robot.robot_id}",
                    details={
                        "anomaly_score": anomaly_score,
                        "anomalous_features": anomalous_features,
                        "battery_level": robot.battery,
                        "position": (robot.x, robot.y),
                        "status": robot.status
                    }
                ))
            except RuntimeError:
                # No event loop available (e.g., during testing)
                pass

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "meta": {
                    "title": "PuppySecOps Platform",
                    "updated_at": time.time(),
                    "mode": "civilian_security_validation",
                    "transport_note": "LBSE over local simulation",
                },
                "map": {
                    "width": self.width,
                    "height": self.height,
                    "obstacles": self.obstacles,
                    "sites": self.sites,
                },
                "robots": [r.to_dict() for r in self.robots.values()],
                "tasks": [t.to_dict() for t in sorted(self.tasks.values(), key=lambda t: (-t.priority, t.created_at))],
                "plans": [p for p in sorted(self.plans.values(), key=lambda p: p.get("created_at", 0), reverse=True)],
                "pending_plans": [p for p in sorted(self.pending_plan_confirmations.values(), key=lambda p: p.get("created_at", 0), reverse=True)],
                "policies": self.policies.to_dict(),
                "security_metrics": dict(self.security_metrics),
                "revoked_certificates": sorted(self.revoked_certificates),
                "audit": [e.to_dict() for e in list(self.audit_log)[:120]],
                "attack_log": list(self.attack_log),
            }

    def bootstrap(self, user: Dict[str, Any]) -> Dict[str, Any]:
        state = self.snapshot()
        state["user"] = user
        return state

    # -----------------------------
    # 任务提交（控制台 -> control）
    # -----------------------------
    def submit_nl_task(self, text: str, requested_by: str) -> Dict[str, Any]:
        task = parse_natural_task(text, requested_by=requested_by)
        return self.submit_signed_task(task, actor=requested_by)

    def submit_signed_task(self, task_data: Dict[str, Any], actor: str, source: str = "ui", auto_assign: bool = True) -> Dict[str, Any]:
        with self.lock:
            packet = self.lbse.seal(
                msg_type="SubmitTask",
                sender_id=f"user:{actor}",
                receiver_id="control",
                session_id=f"user:{actor}->control",
                role="operator",
                task_id=task_data["task_id"],
                lease_id=None,
                payload=task_data,
            )
            return self._control_receive_submit(packet, actor=actor, source=source, auto_assign=auto_assign)

    def _control_receive_submit(self, packet: Dict[str, Any], actor: str, source: str, auto_assign: bool = True) -> Dict[str, Any]:
        try:
            _, payload = self.lbse.open_and_verify(
                packet,
                expected_receiver="control",
                revoked_set=None,
                active_lease_lookup=None,
            )
        except LBSEError as exc:
            self.security_metrics["blocked_injections"] += 1
            self.log("warn", "security", "submit_task_rejected", {"reason": str(exc), "actor": actor})
            return {"ok": False, "reason": str(exc)}

        task_id = payload["task_id"]
        if task_id in self.tasks and self.tasks[task_id].status not in {"completed", "failed", "canceled"}:
            self.log("warn", "security", "duplicate_task_id_rejected", {"task_id": task_id})
            return {"ok": False, "reason": "duplicate_task_id"}

        task = Task(
            task_id=task_id,
            site=payload["site"],
            x=int(payload["x"]),
            y=int(payload["y"]),
            priority=int(payload["priority"]),
            cargo_type=payload.get("cargo_type", "supply"),
            note=payload.get("note", ""),
            requested_by=actor,
            source=source,
            plan_id=payload.get("plan_id"),
            step_id=payload.get("step_id"),
            plan_mode=payload.get("plan_mode"),
            preferred_robot=payload.get("preferred_robot"),
            created_at=time.time(),
            updated_at=time.time(),
        )
        self.tasks[task.task_id] = task
        self.log("info", "task", "task_received", {
            "task_id": task.task_id,
            "site": task.site,
            "priority": task.priority,
            "cargo_type": task.cargo_type,
            "source": source,
            "plan_id": task.plan_id,
            "step_id": task.step_id,
        })
        # 普通单任务提交时立即尝试调度；PlanIR 批量激活多个 ready step 时，
        # 会先把所有 step 编译成 queued task，再统一调用一次 _assign_waiting_tasks()。
        # 这样并行计划不会表现成“提交 s1→调度 s1→再提交 s2”的串行激活。
        if auto_assign:
            self._assign_waiting_tasks()
        return {"ok": True, "task_id": task.task_id}

    # -----------------------------
    # LBSE 关键原语：AssignTask
    # -----------------------------
    def _assign_waiting_tasks(self) -> None:
        queued_tasks = [t for t in self.tasks.values() if t.status == "queued"]
        queued_tasks.sort(key=lambda t: (-t.priority, t.created_at))

        for task in queued_tasks:
            candidates = []
            for robot in self.robots.values():
                if robot.revoked or robot.offline or robot.paused:
                    continue
                if robot.status != "idle":
                    continue
                if robot.battery < 18.0:
                    continue
                if task.site not in robot.zone_access:
                    continue

                path = self.planner.find_path((robot.x, robot.y), (task.x, task.y))
                if not path:
                    continue
                score = len(path) + max(0, 20 - int(robot.battery / 5))
                # Sequential plans may prefer the robot that completed the previous step.
                if task.preferred_robot and robot.robot_id != task.preferred_robot:
                    score += 1000
                candidates.append((score, robot.robot_id, path))

            if not candidates:
                continue

            _, robot_id, path = min(candidates, key=lambda item: item[0])
            version = self.assignment_versions.get(task.task_id, 0) + 1
            self.assignment_versions[task.task_id] = version
            lease_id = f"{task.task_id}#{version}"

            # 更新 control 侧活动租约
            self.active_assignments[task.task_id] = {
                "robot_id": robot_id,
                "lease_id": lease_id,
                "active": True,
            }

            task.status = "assigned"
            task.assigned_robot = robot_id
            task.lease_id = lease_id
            task.updated_at = time.time()
            task.attempts += 1

            payload = {
                "x": task.x,
                "y": task.y,
                "site": task.site,
                "priority": task.priority,
                "cargo_type": task.cargo_type,
                "note": task.note,
                "plan_id": task.plan_id,
                "step_id": task.step_id,
                "plan_mode": task.plan_mode,
            }
            packet = self.lbse.seal(
                msg_type="AssignTask",
                sender_id="control",
                receiver_id=robot_id,
                session_id=f"control->{robot_id}",
                role="dispatcher",
                task_id=task.task_id,
                lease_id=lease_id,
                payload=payload,
            )
            self.log("info", "dispatch", "assign_task_sealed", {
                "task_id": task.task_id,
                "robot_id": robot_id,
                "lease_id": lease_id,
                "plan_id": task.plan_id,
                "step_id": task.step_id,
            })
            self._robot_receive_assign(packet, proposed_path=path)

    def _robot_receive_assign(self, packet: Dict[str, Any], proposed_path: List[tuple[int, int]]) -> None:
        header = packet["header"]
        robot_id = header["receiver_id"]
        robot = self.robots[robot_id]

        if robot.revoked or robot.offline:
            self.log("warn", "dispatch", "assign_rejected_by_robot_state", {
                "robot_id": robot_id,
                "task_id": header["task_id"],
                "reason": "revoked_or_offline",
            })
            return

        try:
            header, payload = self.lbse.open_and_verify(
                packet,
                expected_receiver=robot_id,
                revoked_set=self.revoked_certificates,
                active_lease_lookup=None,
            )
        except LBSEError as exc:
            self.security_metrics["blocked_injections"] += 1
            self.log("warn", "security", "assign_task_verify_failed", {
                "robot_id": robot_id,
                "task_id": packet["header"].get("task_id"),
                "reason": str(exc),
            })
            return

        task_id = header["task_id"]
        lease_id = header["lease_id"]

        robot.status = "enroute"
        robot.current_task_id = task_id
        robot.current_lease_id = lease_id
        robot.path = list(proposed_path)
        robot.assigned_site = payload["site"]

        # 前端“任务总体态势/任务队列”看的是 Task.status。
        # 旧版本只把 Robot.status 改成 enroute，但 Task.status 仍停留在 assigned，
        # 并行计划在 UI 上容易被误看成“第一个任务完成后第二个才开始”。
        # 机器人确认接收任务后，将对应 Task 显式标记为 running。
        task = self.tasks.get(task_id)
        if task:
            task.status = "running"
            task.updated_at = time.time()
        
        # Track task start time for completion time metrics (Task 21.4)
        self.robot_task_start_times[task_id] = time.time()

        self.log("info", "robot", "assignment_accepted", {
            "robot_id": robot_id,
            "task_id": task_id,
            "lease_id": lease_id,
            "path_len": len(robot.path),
        })

        ack_packet = self.lbse.seal(
            msg_type="AckAssignment",
            sender_id=robot_id,
            receiver_id="control",
            session_id=f"{robot_id}->control",
            role="executor",
            task_id=task_id,
            lease_id=lease_id,
            payload={"accepted": True},
        )
        self._control_receive_ack(ack_packet)

    def _control_receive_ack(self, packet: Dict[str, Any]) -> None:
        try:
            header, payload = self.lbse.open_and_verify(
                packet,
                expected_receiver="control",
                revoked_set=self.revoked_certificates,
                active_lease_lookup=lambda task_id: self.active_assignments.get(task_id),
            )
            self.log("info", "dispatch", "assignment_ack_verified", {
                "robot_id": header["sender_id"],
                "task_id": header["task_id"],
                "lease_id": header["lease_id"],
                "accepted": payload["accepted"],
            })
        except LBSEError as exc:
            self.log("warn", "security", "assignment_ack_rejected", {"reason": str(exc)})

    # -----------------------------
    # LBSE 关键原语：Heartbeat
    # -----------------------------
    def _robot_emit_heartbeat(self, robot: Robot) -> None:
        if robot.revoked or robot.offline:
            return

        packet = self.lbse.seal(
            msg_type="Heartbeat",
            sender_id=robot.robot_id,
            receiver_id="control",
            session_id=f"{robot.robot_id}->control",
            role="executor",
            task_id=robot.current_task_id,
            lease_id=robot.current_lease_id,
            payload={
                "x": robot.x,
                "y": robot.y,
                "battery": round(robot.battery, 2),
                "status": robot.status,
            },
        )
        self._control_receive_heartbeat(packet)

    def _control_receive_heartbeat(self, packet: Dict[str, Any]) -> None:
        try:
            header, payload = self.lbse.open_and_verify(
                packet,
                expected_receiver="control",
                revoked_set=self.revoked_certificates,
                active_lease_lookup=lambda task_id: self.active_assignments.get(task_id),
            )
        except LBSENonceReplayError as exc:
            self.security_metrics["blocked_replays"] += 1
            self.log("warn", "security", "heartbeat_blocked", {"reason": str(exc)})
            return
        except LBSELeaseError as exc:
            self.security_metrics["blocked_invalid_completions"] += 1
            self.log("warn", "security", "heartbeat_stale_lease_blocked", {"reason": str(exc)})
            return
        except LBSERevokedError as exc:
            self.security_metrics["blocked_spoofs"] += 1
            self.log("warn", "security", "heartbeat_revoked_sender_blocked", {"reason": str(exc)})
            return
        except LBSEError as exc:
            self.security_metrics["blocked_spoofs"] += 1
            self.log("warn", "security", "heartbeat_verify_failed", {"reason": str(exc)})
            return

        robot = self.robots[header["sender_id"]]
        robot.last_heartbeat = time.time()
        robot.battery = float(payload["battery"])
        # 注意：位置与状态可以作为观测更新，但不覆盖本地 revoked/paused 标志
        robot.x = int(payload["x"])
        robot.y = int(payload["y"])
        
        # Analyze robot behavior for anomalies (Task 21.4)
        self._analyze_robot_behavior(robot)

    # -----------------------------
    # LBSE 关键原语：CompleteTask
    # -----------------------------
    def _robot_emit_complete(self, robot: Robot) -> None:
        if not robot.current_task_id or not robot.current_lease_id:
            return

        packet = self.lbse.seal(
            msg_type="CompleteTask",
            sender_id=robot.robot_id,
            receiver_id="control",
            session_id=f"{robot.robot_id}->control",
            role="executor",
            task_id=robot.current_task_id,
            lease_id=robot.current_lease_id,
            payload={"result": "success", "battery": round(robot.battery, 2)},
        )
        self._control_receive_complete(packet)

    def _control_receive_complete(self, packet: Dict[str, Any]) -> None:
        try:
            header, payload = self.lbse.open_and_verify(
                packet,
                expected_receiver="control",
                revoked_set=self.revoked_certificates,
                active_lease_lookup=lambda task_id: self.active_assignments.get(task_id),
            )
        except LBSENonceReplayError as exc:
            self.security_metrics["blocked_replays"] += 1
            self.log("warn", "security", "completion_blocked_replay", {"reason": str(exc)})
            return
        except LBSELeaseError as exc:
            self.security_metrics["blocked_invalid_completions"] += 1
            self.log("warn", "security", "completion_blocked_lease", {"reason": str(exc)})
            return
        except LBSEError as exc:
            self.security_metrics["blocked_invalid_completions"] += 1
            self.log("warn", "security", "completion_verify_failed", {"reason": str(exc)})
            return

        task_id = header["task_id"]
        lease_id = header["lease_id"]
        robot_id = header["sender_id"]

        if self.policies.idempotent_completion and lease_id in self.completed_leases:
            self.security_metrics["blocked_invalid_completions"] += 1
            self.log("warn", "security", "duplicate_completion_ignored", {
                "task_id": task_id,
                "robot_id": robot_id,
                "lease_id": lease_id,
            })
            return

        task = self.tasks.get(task_id)
        active = self.active_assignments.get(task_id)
        if not task or not active:
            self.security_metrics["blocked_invalid_completions"] += 1
            self.log("warn", "security", "completion_without_active_assignment", {
                "task_id": task_id,
                "robot_id": robot_id,
            })
            return

        self.completed_leases.add(lease_id)
        active["active"] = False
        task.status = "completed"
        task.updated_at = time.time()

        robot = self.robots[robot_id]
        robot.status = "idle"
        robot.current_task_id = None
        robot.current_lease_id = None
        robot.path = []
        robot.assigned_site = None

        self.log("info", "task", "task_completed", {
            "task_id": task_id,
            "robot_id": robot_id,
            "lease_id": lease_id,
            "battery": payload["battery"],
        })
        self._notify_plan_task_completed(task_id=task_id, robot_id=robot_id, lease_id=lease_id)

    # -----------------------------
    # PlanIR 长难句计划编排
    # -----------------------------
    def _hash_plan(self, plan_ir: Dict[str, Any]) -> str:
        material = {
            "raw_text": plan_ir.get("raw_text"),
            "mode": plan_ir.get("mode"),
            "steps": plan_ir.get("steps", []),
        }
        return hashlib.sha256(json.dumps(material, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:16]

    def store_pending_plan(self, plan_ir: Dict[str, Any], guard_result: Dict[str, Any], actor: str) -> Dict[str, Any]:
        """Store a safe-but-complex plan and wait for human confirmation."""
        with self.lock:
            plan_id = plan_ir.get("plan_id") or f"plan_{int(time.time() * 1000) % 100000}"
            plan_ir["plan_id"] = plan_id
            plan_ir["status"] = "pending_confirmation"
            plan_ir["plan_hash"] = self._hash_plan(plan_ir)
            plan_ir["created_at"] = time.time()
            plan_ir["requested_by"] = actor
            plan_ir["guard"] = guard_result
            self.pending_plan_confirmations[plan_id] = plan_ir
            self.log("warn", "TaskGuard", "TaskGuard_need_confirmation", {
                "stage": "TaskGuard",
                "guard_engine": "TaskGuard-S",
                "label_schema": guard_result.get("label_schema", "taskguard"),
                "plan_id": plan_id,
                "mode": plan_ir.get("mode"),
                "step_count": len(plan_ir.get("steps", [])),
                "decision": guard_result.get("decision", "need_confirmation"),
                "risk_level": guard_result.get("risk_level", "medium"),
                "risk_score": guard_result.get("risk_score", 0.55),
                "risk_tags": guard_result.get("risk_tags", ["complex_task"]),
                "reasons": guard_result.get("reasons", []),
                "plan_hash": plan_ir["plan_hash"],
                "actor": actor,
            })
            preview = self._plan_preview(plan_ir)
            preview["plan_hash"] = plan_ir["plan_hash"]
            preview["risk_tags"] = guard_result.get("risk_tags", ["complex_task"])
            preview["reasons"] = guard_result.get("reasons", [])

            return {
                "ok": False,
                "stage": "plan_need_confirmation",
                "confirmation_type": "complex_task",
                "guard_stage": "TaskGuard",
                "decision": "need_confirmation",
                "message": "检测到长难句/多步骤任务，需要确认系统解析出的计划后再执行",
                "plan_id": plan_id,
                "plan_hash": plan_ir["plan_hash"],
                "mode": plan_ir.get("mode"),
                "risk_level": guard_result.get("risk_level", "medium"),
                "risk_score": guard_result.get("risk_score", 0.55),
                "risk_tags": guard_result.get("risk_tags", ["complex_task"]),
                "reasons": guard_result.get("reasons", []),
                "plan_preview": preview,
                "confirm_endpoint": "/api/plans/confirm",
            }

    def _plan_preview(self, plan_ir: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "plan_id": plan_ir.get("plan_id"),
            "mode": plan_ir.get("mode"),
            "raw_text": plan_ir.get("raw_text"),
            "steps": [
                {
                    "step_id": s.get("step_id"),
                    "site": s.get("site"),
                    "cargo_type": s.get("cargo_type"),
                    "priority": s.get("priority"),
                    "depends_on": s.get("depends_on", []),
                    "assignee": s.get("assignee"),
                    "note": s.get("note"),
                }
                for s in plan_ir.get("steps", [])
            ],
        }

    def confirm_plan(self, plan_id: str, actor: str, plan_hash: Optional[str] = None) -> Dict[str, Any]:
        """Confirm a pending PlanIR and activate ready steps.

        Important: confirming a Plan does not create one big lease. Each activated step is
        compiled into a normal Task and obtains its own lease during dispatch.
        """
        with self.lock:
            plan = self.pending_plan_confirmations.pop(plan_id, None)
            if not plan:
                plan = self.plans.get(plan_id)
            if not plan:
                return {"ok": False, "reason": "plan_not_found"}
            if plan.get("status") not in {"pending_confirmation", "approved", "running"}:
                return {"ok": False, "reason": f"plan_status_{plan.get('status')}"}
            if plan_hash and plan.get("plan_hash") and plan_hash != plan.get("plan_hash"):
                self.log("warn", "TaskGuard", "plan_hash_mismatch", {
                    "plan_id": plan_id,
                    "actor": actor,
                    "expected": plan.get("plan_hash"),
                    "received": plan_hash,
                })
                return {"ok": False, "reason": "plan_hash_mismatch"}

            plan["status"] = "approved"
            plan["confirmed_at"] = time.time()
            plan["confirmed_by"] = actor
            for step in plan.get("steps", []):
                step.setdefault("status", "pending")
                step.setdefault("task_id", None)
                step.setdefault("assigned_robot", None)
                step.setdefault("lease_id", None)
            self.plans[plan_id] = plan
            self.log("info", "plan", "plan_confirmed", {
                "plan_id": plan_id,
                "mode": plan.get("mode"),
                "actor": actor,
                "plan_hash": plan.get("plan_hash"),
            })
            self._start_ready_plan_steps(plan_id)
            return {
                "ok": True,
                "plan_id": plan_id,
                "status": self.plans[plan_id].get("status"),
                "started_tasks": [s.get("task_id") for s in self.plans[plan_id].get("steps", []) if s.get("task_id")],
                "message": "计划已确认，系统将按依赖关系逐步激活子任务",
            }

    def cancel_pending_plan(self, plan_id: str, actor: str) -> Dict[str, Any]:
        with self.lock:
            plan = self.pending_plan_confirmations.pop(plan_id, None)
            if not plan:
                return {"ok": False, "reason": "plan_not_found"}
            plan["status"] = "canceled"
            self.plans[plan_id] = plan
            self.log("warn", "plan", "plan_confirmation_canceled", {"plan_id": plan_id, "actor": actor})
            return {"ok": True, "plan_id": plan_id, "status": "canceled"}

    def _dependencies_done(self, plan: Dict[str, Any], step: Dict[str, Any]) -> bool:
        steps = {s.get("step_id"): s for s in plan.get("steps", [])}
        for dep in step.get("depends_on", []) or []:
            if steps.get(dep, {}).get("status") != "completed":
                return False
        return True

    def _start_ready_plan_steps(self, plan_id: str) -> None:
        plan = self.plans.get(plan_id)
        if not plan:
            return

        ready_steps = []
        for step in plan.get("steps", []):
            if step.get("status") != "pending":
                continue
            if not self._dependencies_done(plan, step):
                continue
            ready_steps.append(step)

        # 并行计划的关键：先把同一批 ready step 全部编译成 queued task，
        # 再统一调度一次。否则每编译一个 step 都立刻调度，前端日志会明显显示
        # “s1 先执行、s2 后执行”，容易被误解为顺序计划。
        started = []
        for step in ready_steps:
            task_id = self._compile_and_submit_plan_step(plan, step, auto_assign=False)
            if task_id:
                started.append(task_id)

        if started:
            self._assign_waiting_tasks()

            # 调度完成后回填每个 step 的机器人和租约。
            for step in ready_steps:
                task_id = step.get("task_id")
                task = self.tasks.get(task_id) if task_id else None
                if task:
                    step["status"] = "running" if task.status in {"assigned", "queued"} else task.status
                    step["assigned_robot"] = task.assigned_robot
                    step["lease_id"] = task.lease_id

            plan["status"] = "running"
            self.log("info", "plan", "plan_steps_activated", {"plan_id": plan_id, "task_ids": started})
        self._refresh_plan_status(plan)

    def _compile_and_submit_plan_step(self, plan: Dict[str, Any], step: Dict[str, Any], auto_assign: bool = True) -> Optional[str]:
        plan_id = plan["plan_id"]
        step_id = step["step_id"]
        task_id = step.get("task_id") or f"{plan_id}_{step_id}"
        if task_id in self.tasks and self.tasks[task_id].status not in {"completed", "failed", "canceled"}:
            return task_id

        preferred_robot = None
        assignee = step.get("assignee") or {"type": "auto"}
        if assignee.get("type") == "same_as":
            same_step_id = assignee.get("same_as_step")
            for prev in plan.get("steps", []):
                if prev.get("step_id") == same_step_id:
                    preferred_robot = prev.get("assigned_robot")
                    break

        task_data = {
            "task_id": task_id,
            "site": step["site"],
            "x": step["x"],
            "y": step["y"],
            "priority": step.get("priority", 3),
            "cargo_type": step.get("cargo_type", "supply"),
            "note": f"[Plan {plan_id}/{step_id}] {step.get('note', plan.get('raw_text', ''))}",
            "requested_by": plan.get("requested_by", "operator"),
            "source": "plan_ir",
            "plan_id": plan_id,
            "step_id": step_id,
            "plan_mode": plan.get("mode"),
            "preferred_robot": preferred_robot,
        }
        step["task_id"] = task_id
        step["status"] = "queued"
        result = self.submit_signed_task(task_data, actor=plan.get("requested_by", "operator"), source="plan_ir", auto_assign=auto_assign)
        if result.get("ok"):
            self.task_plan_index[task_id] = {"plan_id": plan_id, "step_id": step_id}
            task = self.tasks.get(task_id)
            if task:
                step["status"] = "running" if task.status in {"assigned", "queued"} else task.status
                step["assigned_robot"] = task.assigned_robot
                step["lease_id"] = task.lease_id
            return task_id
        step["status"] = "failed"
        step["failure_reason"] = result.get("reason", "submit_failed")
        self.log("warn", "plan", "plan_step_submit_failed", {"plan_id": plan_id, "step_id": step_id, "reason": step["failure_reason"]})
        return None

    def _notify_plan_task_completed(self, task_id: str, robot_id: str, lease_id: str) -> None:
        ref = self.task_plan_index.get(task_id)
        if not ref:
            return
        plan = self.plans.get(ref["plan_id"])
        if not plan:
            return
        for step in plan.get("steps", []):
            if step.get("step_id") == ref["step_id"]:
                step["status"] = "completed"
                step["assigned_robot"] = robot_id
                step["lease_id"] = lease_id
                break
        self.log("info", "plan", "plan_step_completed", {
            "plan_id": ref["plan_id"],
            "step_id": ref["step_id"],
            "task_id": task_id,
            "robot_id": robot_id,
            "lease_id": lease_id,
        })
        self._start_ready_plan_steps(ref["plan_id"])

    def _refresh_plan_status(self, plan: Dict[str, Any]) -> None:
        statuses = [s.get("status") for s in plan.get("steps", [])]
        if statuses and all(status == "completed" for status in statuses):
            plan["status"] = "completed"
            self.log("info", "plan", "plan_completed", {"plan_id": plan.get("plan_id"), "mode": plan.get("mode")})
        elif any(status in {"running", "queued"} for status in statuses):
            plan["status"] = "running"

    # -----------------------------
    # 任务回收 / 吊销 / 失陷
    # -----------------------------
    def _cancel_assignment(self, task_id: str, robot_id: str, reason: str) -> None:
        task = self.tasks.get(task_id)
        robot = self.robots.get(robot_id)

        if task:
            task.status = "queued"
            task.assigned_robot = None
            task.updated_at = time.time()

        active = self.active_assignments.get(task_id)
        if active:
            active["active"] = False

        if robot and robot.current_task_id == task_id:
            cancel_packet = self.lbse.seal(
                msg_type="CancelTask",
                sender_id="control",
                receiver_id=robot_id,
                session_id=f"control->{robot_id}",
                role="dispatcher",
                task_id=task_id,
                lease_id=robot.current_lease_id,
                payload={"reason": reason},
            )
            self._robot_receive_cancel(cancel_packet)

        self.log("warn", "dispatch", "task_canceled_or_reclaimed", {
            "task_id": task_id,
            "robot_id": robot_id,
            "reason": reason,
        })

    def _robot_receive_cancel(self, packet: Dict[str, Any]) -> bool:
        try:
            header, payload = self.lbse.open_and_verify(
                packet,
                expected_receiver=packet["header"]["receiver_id"],
                revoked_set=self.revoked_certificates,
                active_lease_lookup=None,
            )
        except LBSEError as exc:
            self.log("warn", "security", "cancel_rejected", {"reason": str(exc)})
            return False

        robot = self.robots[header["receiver_id"]]
        if robot.current_task_id == header["task_id"] and robot.current_lease_id == header["lease_id"]:
            robot.current_task_id = None
            robot.current_lease_id = None
            robot.path = []
            robot.status = "idle" if not robot.revoked else "revoked"
            robot.assigned_site = None
            self.log("warn", "robot", "cancel_applied", {
                "robot_id": robot.robot_id,
                "task_id": header["task_id"],
                "lease_id": header["lease_id"],
                "reason": payload["reason"],
            })
            return True
        return False

    def control_cancel_task(self, task_id: str, actor: str, reason: str = "operator_cancel") -> Dict[str, Any]:
        with self.lock:
            task = self.tasks.get(task_id)
            if not task:
                return {"ok": False, "reason": "task_not_found"}
            if task.status in {"completed", "canceled", "failed"}:
                return {"ok": False, "reason": f"task_already_{task.status}"}

            robot_id = task.assigned_robot
            lease_id = task.lease_id
            if not robot_id or not lease_id:
                task.status = "canceled"
                task.updated_at = time.time()
                self.log("warn", "control", "task_canceled_without_active_robot", {
                    "task_id": task_id,
                    "actor": actor,
                    "reason": reason,
                })
                return {"ok": True, "task_id": task_id, "canceled": True}

            packet = self.lbse.seal(
                msg_type="CancelTask",
                sender_id="control",
                receiver_id=robot_id,
                session_id=f"control->{robot_id}",
                role="dispatcher",
                task_id=task_id,
                lease_id=lease_id,
                payload={"reason": reason, "actor": actor},
            )
            self.log("info", "control", "cancel_task_sealed", {
                "task_id": task_id,
                "robot_id": robot_id,
                "lease_id": lease_id,
                "actor": actor,
            })
            accepted = self._robot_receive_cancel(packet)
            if not accepted:
                self.log("warn", "control", "cancel_task_not_applied", {
                    "task_id": task_id,
                    "robot_id": robot_id,
                    "lease_id": lease_id,
                })
                return {"ok": False, "reason": "cancel_not_applied"}

            active = self.active_assignments.get(task_id)
            if active:
                active["active"] = False
            task.status = "canceled"
            task.assigned_robot = None
            task.lease_id = None
            task.updated_at = time.time()
            self.log("warn", "control", "task_canceled", {
                "task_id": task_id,
                "actor": actor,
                "reason": reason,
            })
            return {"ok": True, "task_id": task_id, "canceled": True}

    def control_revoke_robot(self, robot_id: str, actor: str, reason: str = "manual_revoke") -> Dict[str, Any]:
        with self.lock:
            robot = self.robots.get(robot_id)
            if not robot:
                return {"ok": False, "reason": "robot_not_found"}
            packet = self.lbse.seal(
                msg_type="RevokeRobot",
                sender_id="control",
                receiver_id=robot_id,
                session_id=f"control->{robot_id}",
                role="security_admin",
                task_id=robot.current_task_id,
                lease_id=robot.current_lease_id,
                payload={"reason": reason, "actor": actor},
            )
            self.log("critical", "control", "revoke_robot_sealed", {
                "robot_id": robot_id,
                "actor": actor,
                "reason": reason,
            })
            return self._robot_receive_revoke(packet)

    def _robot_receive_revoke(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        try:
            header, payload = self.lbse.open_and_verify(
                packet,
                expected_receiver=packet["header"]["receiver_id"],
                revoked_set=None,
                active_lease_lookup=None,
            )
        except LBSEError as exc:
            self.log("warn", "security", "revoke_rejected", {"reason": str(exc)})
            return {"ok": False, "reason": str(exc)}

        robot_id = header["receiver_id"]
        robot = self.robots[robot_id]
        current_task_id = robot.current_task_id

        robot.revoked = True
        robot.compromised = False
        robot.offline = False
        robot.status = "revoked"
        robot.path = []
        robot.current_task_id = None
        robot.current_lease_id = None
        robot.assigned_site = None

        self.revoked_certificates.add(robot_id)
        self.security_metrics["revoked_robots"] += 1
        self.log("critical", "security", "robot_revoked_via_lbse", {
            "robot_id": robot_id,
            "reason": payload["reason"],
            "actor": payload.get("actor"),
        })

        if current_task_id:
            task = self.tasks.get(current_task_id)
            active = self.active_assignments.get(current_task_id)
            if active:
                active["active"] = False
            if task and task.status not in {"completed", "failed", "canceled"}:
                task.status = "queued"
                task.assigned_robot = None
                task.lease_id = None
                task.updated_at = time.time()
                self.log("warn", "dispatch", "task_requeued_after_revoke", {
                    "task_id": current_task_id,
                    "robot_id": robot_id,
                })
                self._assign_waiting_tasks()

            return {"ok": True, "robot_id": robot_id, "requeued_task": current_task_id}

        return {"ok": True, "robot_id": robot_id}

    def revoke_robot(self, robot_id: str, reason: str) -> None:
        """兼容旧调用：内部转为 LBSE 风格吊销。"""
        self.control_revoke_robot(robot_id=robot_id, actor="system", reason=reason)

    def recover_robot(self, robot_id: str) -> Dict[str, Any]:
        with self.lock:
            robot = self.robots[robot_id]
            robot.revoked = False
            robot.compromised = False
            robot.offline = False
            robot.status = "idle"
            robot.current_task_id = None
            robot.current_lease_id = None
            robot.path = []
            self.revoked_certificates.discard(robot_id)
            self.log("info", "security", "robot_recovered", {"robot_id": robot_id})
            return {"ok": True}

    # -----------------------------
    # 攻击实验接口（保持 routes 兼容）
    # -----------------------------
    def attack_unsigned_injection(self, task_data: Dict[str, Any], actor: str = "attack_lab") -> Dict[str, Any]:
        with self.lock:
            # 伪造一个没有 LBSE 结构的“消息”
            fake_packet = {"header": {"sender_id": actor}, "ciphertext": "x", "nonce": "y"}
            try:
                self._control_receive_submit(fake_packet, actor=actor, source="attack")
            except Exception:
                pass
            self.security_metrics["blocked_injections"] += 1
            self.attack_log.appendleft({"ts": time.time(), "type": "unsigned_injection", "result": "blocked"})
            self.log("warn", "attack", "unsigned_injection_blocked", {"actor": actor})
            return {"ok": False, "reason": "missing_valid_lbse"}

    def attack_replay(self, task_data: Dict[str, Any], actor: str = "attack_lab") -> Dict[str, Any]:
        with self.lock:
            packet = self.lbse.seal(
                msg_type="SubmitTask",
                sender_id=actor,
                receiver_id="control",
                session_id=f"{actor}->control",
                role="attacker",
                task_id=task_data["task_id"],
                lease_id=None,
                payload=task_data,
            )
            first = self._control_receive_submit(packet, actor=actor, source="attack")
            # 第二次重放同一 packet
            second = self._control_receive_submit(packet, actor=actor, source="attack")
            if not second.get("ok", False):
                self.security_metrics["blocked_replays"] += 1
                self.attack_log.appendleft({"ts": time.time(), "type": "replay", "result": "blocked"})
                self.log("warn", "attack", "replay_blocked", {"task_id": task_data["task_id"]})
            return second

    def attack_heartbeat_spoof(self, robot_id: str) -> Dict[str, Any]:
        with self.lock:
            robot = self.robots[robot_id]
            # 构造伪造 heartbeat，故意使用错误 receiver / 缺少合法路径
            fake_packet = {
                "header": {
                    "version": 1,
                    "msg_type": "Heartbeat",
                    "sender_id": robot_id,
                    "receiver_id": "control",
                    "session_id": f"{robot_id}->control",
                    "seq": 1,
                    "timestamp_ms": int(time.time() * 1000),
                    "task_id": robot.current_task_id,
                    "lease_id": robot.current_lease_id,
                    "role": "executor",
                    "key_id": "lbse-k1",
                },
                "nonce": "AAAA",
                "ciphertext": "BBBB",
            }
            self._control_receive_heartbeat(fake_packet)
            self.attack_log.appendleft({"ts": time.time(), "type": "heartbeat_spoof", "result": "blocked"})
            return {"ok": False, "reason": "invalid_lbse"}

    def compromise_robot(self, robot_id: str) -> Dict[str, Any]:
        with self.lock:
            robot = self.robots[robot_id]
            robot.compromised = True
            self.log("critical", "attack", "robot_marked_compromised", {"robot_id": robot_id})
            self.attack_log.appendleft({"ts": time.time(), "type": "compromise_robot", "result": "success", "robot_id": robot_id})
            return {"ok": True}

    def attack_mitm(self, robot_id: str, target_site: str) -> Dict[str, Any]:
        """中间人攻击 - 尝试拦截机器人与控制中心的通信"""
        with self.lock:
            robot = self.robots.get(robot_id)
            if not robot:
                return {"ok": False, "reason": "robot_not_found"}
            
            # 检查是否有加密保护
            if self.policies.require_signed_commands:
                # 有签名保护，攻击被阻断
                self.security_metrics["blocked_spoofs"] += 1
                self.attack_log.appendleft({
                    "ts": time.time(), 
                    "type": "mitm_attack", 
                    "result": "blocked",
                    "robot_id": robot_id,
                    "reason": "encrypted_channel"
                })
                self.log("warn", "attack", "mitm_blocked", {
                    "robot_id": robot_id, 
                    "target_site": target_site,
                    "reason": "channel_encryption_active"
                })
                return {"ok": False, "reason": "encrypted_channel"}
            else:
                # 无保护，攻击成功
                self.attack_log.appendleft({
                    "ts": time.time(), 
                    "type": "mitm_attack", 
                    "result": "success",
                    "robot_id": robot_id
                })
                self.log("critical", "attack", "mitm_succeeded", {
                    "robot_id": robot_id,
                    "target_site": target_site
                })
                return {"ok": True, "intercepted": True}

    def attack_ddos(self, target: str, intensity: str = "medium") -> Dict[str, Any]:
        """DDoS攻击 - 大量请求淹没系统"""
        with self.lock:
            # 根据强度计算请求数量
            request_counts = {"low": 100, "medium": 500, "high": 1000}
            request_count = request_counts.get(intensity, 500)
            
            # 检查是否有速率限制保护
            if self.policies.strict_mode:
                # 严格模式下有速率限制，攻击被阻断
                self.security_metrics["blocked_injections"] += 1
                self.attack_log.appendleft({
                    "ts": time.time(),
                    "type": "ddos_attack",
                    "result": "blocked",
                    "target": target,
                    "intensity": intensity,
                    "requests": request_count,
                    "reason": "rate_limit_active"
                })
                self.log("warn", "attack", "ddos_blocked", {
                    "target": target,
                    "intensity": intensity,
                    "requests": request_count,
                    "reason": "rate_limiting"
                })
                return {"ok": False, "reason": "rate_limit_protection"}
            else:
                # 无保护，系统可能受影响
                self.attack_log.appendleft({
                    "ts": time.time(),
                    "type": "ddos_attack",
                    "result": "partial_success",
                    "target": target,
                    "intensity": intensity,
                    "requests": request_count
                })
                self.log("critical", "attack", "ddos_partial", {
                    "target": target,
                    "intensity": intensity,
                    "requests": request_count
                })
                return {"ok": True, "impact": "system_slowdown"}

    def attack_privilege_escalation(self, robot_id: str, target_role: str = "admin") -> Dict[str, Any]:
        """权限提升攻击 - 尝试获取更高权限"""
        with self.lock:
            robot = self.robots.get(robot_id)
            if not robot:
                return {"ok": False, "reason": "robot_not_found"}
            
            # 检查是否有权限校验
            if self.policies.least_privilege_topics:
                # 有最小权限保护，攻击被阻断
                self.security_metrics["blocked_injections"] += 1
                self.attack_log.appendleft({
                    "ts": time.time(),
                    "type": "privilege_escalation",
                    "result": "blocked",
                    "robot_id": robot_id,
                    "target_role": target_role,
                    "reason": "privilege_check_active"
                })
                self.log("warn", "attack", "privilege_escalation_blocked", {
                    "robot_id": robot_id,
                    "target_role": target_role,
                    "reason": "least_privilege_enforcement"
                })
                return {"ok": False, "reason": "privilege_check_failed"}
            else:
                # 无保护，攻击可能成功
                self.attack_log.appendleft({
                    "ts": time.time(),
                    "type": "privilege_escalation",
                    "result": "success",
                    "robot_id": robot_id,
                    "target_role": target_role
                })
                self.log("critical", "attack", "privilege_escalation_succeeded", {
                    "robot_id": robot_id,
                    "target_role": target_role
                })
                return {"ok": True, "escalated": True}

    def attack_cert_forge(self, robot_id: str) -> Dict[str, Any]:
        """证书伪造攻击 - 尝试伪造合法证书"""
        with self.lock:
            robot = self.robots.get(robot_id)
            if not robot:
                return {"ok": False, "reason": "robot_not_found"}
            
            # 检查证书是否已被吊销或有验证机制
            if robot.revoked or self.policies.auto_revoke_compromised:
                # 有证书验证，攻击被阻断
                self.security_metrics["blocked_spoofs"] += 1
                self.attack_log.appendleft({
                    "ts": time.time(),
                    "type": "cert_forge",
                    "result": "blocked",
                    "robot_id": robot_id,
                    "reason": "cert_validation_active"
                })
                self.log("warn", "attack", "cert_forge_blocked", {
                    "robot_id": robot_id,
                    "reason": "certificate_validation"
                })
                return {"ok": False, "reason": "cert_validation_failed"}
            else:
                # 无保护，伪造可能成功
                self.attack_log.appendleft({
                    "ts": time.time(),
                    "type": "cert_forge",
                    "result": "success",
                    "robot_id": robot_id
                })
                self.log("critical", "attack", "cert_forge_succeeded", {
                    "robot_id": robot_id
                })
                return {"ok": True, "forged": True}

    # -----------------------------
    # 运行控制接口
    # -----------------------------
    def toggle_policy(self, name: str, value: bool | float) -> Dict[str, Any]:
        with self.lock:
            if hasattr(self.policies, name):
                setattr(self.policies, name, value)
                self.log("info", "policy", "policy_updated", {"name": name, "value": value})
                return {"ok": True}
            return {"ok": False, "reason": "unknown_policy"}

    def set_robot_pause(self, robot_id: str, paused: bool) -> Dict[str, Any]:
        with self.lock:
            robot = self.robots[robot_id]
            robot.paused = paused
            self.log("warn" if paused else "info", "control", "robot_pause_changed", {"robot_id": robot_id, "paused": paused})
            return {"ok": True}

    def set_robot_offline(self, robot_id: str, offline: bool) -> Dict[str, Any]:
        with self.lock:
            robot = self.robots[robot_id]
            robot.offline = offline
            self.log("warn" if offline else "info", "control", "robot_offline_changed", {"robot_id": robot_id, "offline": offline})
            return {"ok": True}

    def build_demo_task(self, site: str, cargo_type: str, priority: int, note: str, task_id: Optional[str] = None, actor: str = "operator") -> Dict[str, Any]:
        if site not in self.sites:
            site = "zone_a"
        x, y = self.sites[site]
        return {
            "task_id": task_id or f"tsk_{int(time.time() * 1000) % 100000}",
            "site": site,
            "x": x,
            "y": y,
            "priority": priority,
            "cargo_type": cargo_type,
            "note": note,
            "requested_by": actor,
            "source": "ui",
        }

    # -----------------------------
    # 时钟推进
    # -----------------------------
    def tick(self) -> None:
        with self.lock:
            now = time.time()
            dt = now - self.last_tick
            self.last_tick = now

            for robot in self.robots.values():
                if robot.revoked:
                    continue

                if robot.compromised and self.policies.auto_revoke_compromised:
                    self.revoke_robot(robot.robot_id, reason="compromised_detected")
                    continue

                if not robot.offline:
                    self._robot_emit_heartbeat(robot)

                if robot.paused or robot.offline:
                    continue

                if robot.status == "charging":
                    if (robot.x, robot.y) == robot.home:
                        robot.battery = min(100.0, robot.battery + 4.0 * max(dt, 0.5))
                        if robot.battery >= 95.0:
                            robot.status = "idle"
                            self.log("info", "robot", "charge_complete", {"robot_id": robot.robot_id, "battery": round(robot.battery, 1)})
                    elif robot.path:
                        self._move_robot_one_step(robot)
                    continue

                if robot.status == "enroute":
                    if robot.path:
                        self._move_robot_one_step(robot)
                    else:
                        self._robot_emit_complete(robot)

                if robot.status == "idle" and robot.battery < 24.0 and not robot.current_task_id:
                    self._send_to_charge(robot)

            self._detect_stale_robots(now)
            self._assign_waiting_tasks()

    def _move_robot_one_step(self, robot: Robot) -> None:
        if not robot.path:
            return
        next_point = robot.path.pop(0)
        robot.x, robot.y = next_point
        robot.battery = max(0.0, robot.battery - 0.8)

    def _send_to_charge(self, robot: Robot) -> None:
        if robot.revoked:
            return
        path = self.planner.find_path((robot.x, robot.y), robot.home)
        robot.path = path
        robot.status = "charging"
        robot.assigned_site = "dock"
        self.log("warn", "energy", "battery_low_charge_dispatch", {
            "robot_id": robot.robot_id,
            "battery": round(robot.battery, 1),
        })

    def _detect_stale_robots(self, now: float) -> None:
        timeout = self.policies.heartbeat_timeout_sec
        for robot in self.robots.values():
            if robot.revoked or not robot.current_task_id:
                continue
            if now - robot.last_heartbeat > timeout:
                task_id = robot.current_task_id
                self.log("critical", "availability", "assignment_reclaimed", {
                    "robot_id": robot.robot_id,
                    "task_id": task_id,
                    "reason": "stale_or_offline",
                })
                self._cancel_assignment(task_id, robot.robot_id, reason="stale_or_offline")