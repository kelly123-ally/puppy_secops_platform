const state = {
  snapshot: null,
  ws: null,
  currentUser: window.__BOOT_USER__ || null,
};

const authToken = localStorage.getItem("psp_token");

const policyLabels = {
  strict_mode: "严格模式",
  require_signed_commands: "强制签名命令",
  replay_protection: "重放保护",
  auto_revoke_compromised: "失陷自动吊销",
  enforce_lease_id: "强制租约校验",
  idempotent_completion: "幂等完成",
  least_privilege_topics: "最小权限 Topic",
  heartbeat_timeout_sec: "心跳超时（秒）",
};

const policyDescriptions = {
  strict_mode: "启用高强度安全校验与防护策略",
  require_signed_commands: "所有任务/控制命令必须带签名",
  replay_protection: "阻断重复 nonce 或过期消息",
  auto_revoke_compromised: "检测到终端失陷后自动吊销",
  enforce_lease_id: "任务完成时校验当前有效租约",
  idempotent_completion: "同一任务只允许一次合法完成",
  least_privilege_topics: "仅允许最小必要的 Topic 访问",
  heartbeat_timeout_sec: "机器人心跳超时阈值",
};

function policyLabel(key) {
  return policyLabels[key] || key;
}

function policyDescription(key) {
  return policyDescriptions[key] || "";
}

function policyValueText(value) {
  if (typeof value === "boolean") {
    return value ? "开启" : "关闭";
  }
  return String(value);
}

const statusLabels = {
  idle: "空闲",
  assigned: "已分配",
  enroute: "执行中",
  completed: "已完成",
  queued: "排队中",
  failed: "失败",
  canceled: "已取消",
  revoked: "已吊销",
  charging: "充电中",
  paused: "已暂停",
};

const auditTitleLabels = {
  platform_boot: "平台启动",
  strict_mode_enabled: "严格模式已启用",
  task_received: "任务已接收",
  task_assigned: "任务已分配",
  task_completed: "任务已完成",
  task_rejected: "任务被拒绝",
  stale_completion_ignored: "旧租约完成被忽略",
  duplicate_completion_ignored: "重复完成被忽略",
  task_canceled_or_reclaimed: "任务取消或回收",
  robot_revoked: "机器人已吊销",
  robot_recovered: "机器人已恢复",
  robot_marked_compromised: "机器人被标记为失陷",
  spoof_blocked: "伪造攻击被阻断",
  spoof_succeeded: "伪造攻击成功",
  battery_low_charge_dispatch: "低电量自动回充",
  charge_complete: "充电完成",
  path_progress: "路径推进",
  policy_updated: "安全策略已更新",
  robot_pause_changed: "机器人暂停状态变化",
  robot_offline_changed: "机器人离线状态变化",
};

const auditCategoryLabels = {
  system: "系统",
  policy: "策略",
  task: "任务",
  dispatch: "调度",
  security: "安全",
  attack: "攻击",
  motion: "运动",
  control: "控制",
  availability: "可用性",
  energy: "能量",
  robot: "机器人",
};

function statusLabel(status) {
  return statusLabels[status] || status;
}

function auditTitleLabel(title) {
  return auditTitleLabels[title] || title;
}

function auditCategoryLabel(category) {
  return auditCategoryLabels[category] || category;
}

if (!authToken) {
  location.href = "/";
}

const tabs = document.querySelectorAll(".nav-item");
const panels = document.querySelectorAll(".tab-panel");
tabs.forEach(btn => {
  btn.addEventListener("click", () => {
    tabs.forEach(b => b.classList.remove("active"));
    panels.forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await fetch("/api/logout", {method: "POST", headers: authHeaders()});
  localStorage.removeItem("psp_token");
  localStorage.removeItem("psp_user");
  location.href = "/";
});

document.getElementById("nl-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await postJSON("/api/tasks/natural", Object.fromEntries(fd.entries()));
  e.target.reset();
});

document.getElementById("task-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  payload.priority = Number(payload.priority);
  await postJSON("/api/tasks/structured", payload);
  e.target.reset();
});

function authHeaders() {
  return authToken ? {"Authorization": `Bearer ${authToken}`} : {};
}

async function postJSON(url, payload) {
  const resp = await fetch(url, {
    method: "POST",
    headers: {...authHeaders(), "Content-Type": "application/json"},
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const text = await resp.text();
    alert(`请求失败: ${text}`);
    return null;
  }
  return await resp.json();
}

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/stream?token=${encodeURIComponent(authToken)}`);
  state.ws = ws;
  ws.onopen = () => {
    document.getElementById("status-chip").textContent = "实时连接中";
    document.getElementById("status-chip").className = "chip chip-green";
    setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send("ping");
    }, 3000);
  };
  ws.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    state.snapshot = payload;
    if (payload.user) state.currentUser = payload.user;
    render(payload);
  };
  ws.onclose = () => {
    document.getElementById("status-chip").textContent = "连接中断，尝试重连";
    document.getElementById("status-chip").className = "chip chip-red";
    setTimeout(connectWS, 1500);
  };
}
connectWS();

function render(snapshot) {
  renderMetrics(snapshot);
  renderMap(snapshot);
  renderPolicies(snapshot);
  renderCerts(snapshot);
  renderRobots(snapshot);
  renderTasks(snapshot);
  renderRobotControls(snapshot);
  renderSecurityMetrics(snapshot);
  renderPolicyControls(snapshot);
  renderAttackLog(snapshot);
  renderAudit(snapshot);
}

function renderMetrics(snapshot) {
  const robots = snapshot.robots || [];
  const tasks = snapshot.tasks || [];
  const metrics = snapshot.security_metrics || {};
  const online = robots.filter(r => !r.offline && !r.revoked).length;
  const running = tasks.filter(t => t.status === "assigned").length;
  const blocked = (metrics.blocked_injections || 0) + (metrics.blocked_replays || 0) + (metrics.blocked_spoofs || 0);
  const revoked = (snapshot.revoked_certificates || []).length;
  setText("m-online", online);
  setText("m-running", running);
  setText("m-blocked", blocked);
  setText("m-revoked", revoked);
}

function renderPolicies(snapshot) {
  const root = document.getElementById("policy-summary");
  root.innerHTML = "";
  Object.entries(snapshot.policies || {}).forEach(([key, value]) => {
    const label = policyLabel(key);
    const valueText = policyValueText(value);
    const isOn = typeof value === "boolean" ? value : true;

    const div = document.createElement("div");
    div.className = "policy-chip";
    div.innerHTML = `
      <span>${label}</span>
      <span class="status-pill ${isOn ? 'status-completed' : 'status-revoked'}">
        ${valueText}
      </span>
    `;
    root.appendChild(div);
  });
}

function renderCerts(snapshot) {
  const root = document.getElementById("cert-list");
  const revoked = snapshot.revoked_certificates || [];
  root.innerHTML = "";
  if (!revoked.length) {
    root.innerHTML = `<div class="mini-card">当前没有吊销证书。</div>`;
    return;
  }
  revoked.forEach(item => {
    const div = document.createElement("div");
    div.className = "mini-card";
    div.innerHTML = `<strong>${item}</strong><div class="muted">status: revoked</div>`;
    root.appendChild(div);
  });
}

function renderRobots(snapshot) {
  const root = document.getElementById("robot-table");
  const head = document.createElement("div");
  head.className = "table-head table-row robot";
  head.innerHTML = `<div>机器人</div><div>状态</div><div>电量</div><div>位置</div><div>任务</div><div>租约</div>`;
  root.innerHTML = "";
  root.appendChild(head);

  (snapshot.robots || []).forEach(robot => {
    const row = document.createElement("div");
    row.className = "table-row robot";
    row.innerHTML = `
      <div><strong>${robot.robot_id}</strong><div class="muted">${flags(robot)}</div></div>
      <div>${statusPill(robot.status)}</div>
      <div>${robot.battery.toFixed(1)}%</div>
      <div>[${robot.x}, ${robot.y}]</div>
      <div>${robot.current_task_id || "-"}</div>
      <div>${robot.current_lease_id || "-"}</div>
    `;
    root.appendChild(row);
  });
}

function renderTasks(snapshot) {
  const root = document.getElementById("task-table");
  const head = document.createElement("div");
  head.className = "table-head table-row task";
  head.innerHTML = `<div>任务</div><div>站点</div><div>优先级</div><div>状态</div><div>执行机器人</div><div>租约/操作</div>`;
  root.innerHTML = "";
  root.appendChild(head);

  (snapshot.tasks || []).forEach(task => {
    const canCancel = !["completed", "failed", "canceled"].includes(task.status);
    const row = document.createElement("div");
    row.className = "table-row task";
    row.innerHTML = `
      <div><strong>${task.task_id}</strong><div class="muted">${task.cargo_type}</div></div>
      <div>${task.site}</div>
      <div>${task.priority}</div>
      <div>${statusPill(task.status)}</div>
      <div>${task.assigned_robot || "-"}</div>
      <div>
        <div>${task.lease_id || "-"}</div>
        ${canCancel ? `<button class="ghost-btn small-btn cancel-task-btn" data-task="${task.task_id}">取消任务</button>` : ""}
      </div>
    `;
    root.appendChild(row);
  });

  root.querySelectorAll(".cancel-task-btn").forEach(btn => {
    btn.onclick = async () => {
      const taskId = btn.dataset.task;
      await postJSON("/api/tasks/cancel", {
        task_id: taskId,
        reason: "ui_cancel"
      });
    };
  });
}

function renderRobotControls(snapshot) {
  const root = document.getElementById("robot-controls");
  root.innerHTML = "";
  (snapshot.robots || []).forEach(robot => {
    const row = document.createElement("div");
    row.className = "control-row";
    row.innerHTML = `
      <div>
        <div><strong>${robot.robot_id}</strong></div>
        <div class="muted">${statusLabel(robot.status)} · 电量 ${robot.battery.toFixed(1)}%</div>
      </div>
      <div style="display:flex; gap:8px; flex-wrap: wrap;">
        <button class="ghost-btn small-btn" data-action="pause" data-robot="${robot.robot_id}">${robot.paused ? "恢复" : "暂停"}</button>
        <button class="ghost-btn small-btn" data-action="offline" data-robot="${robot.robot_id}">${robot.offline ? "上线" : "离线"}</button>
        <button class="ghost-btn small-btn" data-action="recover" data-robot="${robot.robot_id}">恢复证书</button>
        <button class="danger-btn small-btn" data-action="revoke" data-robot="${robot.robot_id}">吊销机器人</button>
      </div>
    `;
    root.appendChild(row);
  });

  root.querySelectorAll("button").forEach(btn => {
    btn.onclick = async () => {
      const action = btn.dataset.action;
      const robotId = btn.dataset.robot;
      const robot = (snapshot.robots || []).find(r => r.robot_id === robotId);
      if (action === "pause") {
        await postJSON("/api/robots/pause", {robot_id: robotId, paused: !robot.paused});
      } else if (action === "offline") {
        await postJSON("/api/robots/offline", {robot_id: robotId, offline: !robot.offline});
      } else if (action === "recover") {
        await postJSON("/api/robots/recover", {robot_id: robotId});
      } else if (action === "revoke") {
        await postJSON("/api/robots/revoke", {
          robot_id: robotId,
          reason: "ui_manual_revoke"
        });
      }
    };
  });
}

function renderSecurityMetrics(snapshot) {
  const root = document.getElementById("security-metrics");
  root.innerHTML = "";
  Object.entries(snapshot.security_metrics || {}).forEach(([key, value]) => {
    const row = document.createElement("div");
    row.className = "toggle-row";
    row.innerHTML = `<span>${key}</span><strong>${value}</strong>`;
    root.appendChild(row);
  });
}

function renderPolicyControls(snapshot) {
  const root = document.getElementById("policy-controls");
  root.innerHTML = "";
  const user = state.currentUser || { role: "viewer" };

  Object.entries(snapshot.policies || {}).forEach(([key, value]) => {
    const disabled = user.role !== "admin" || typeof value !== "boolean";
    const label = policyLabel(key);
    const desc = policyDescription(key);

    const row = document.createElement("div");
    row.className = "toggle-row";
    row.innerHTML = `
      <div>
        <div><strong>${label}</strong></div>
        <div class="muted">${desc || (typeof value === "boolean" ? "布尔策略" : "数值策略")}</div>
      </div>
      ${
        typeof value === "boolean"
          ? `<div class="switch ${value ? "on" : ""} ${disabled ? "disabled" : ""}" data-key="${key}" data-value="${value}"></div>`
          : `<div>${policyValueText(value)}</div>`
      }
    `;
    root.appendChild(row);
  });

  root.querySelectorAll(".switch").forEach((sw) => {
    if ((state.currentUser || {}).role !== "admin") return;
    sw.onclick = async () => {
      const key = sw.dataset.key;
      const current = sw.dataset.value === "true";
      await postJSON("/api/policies/update", { name: key, value: !current });
    };
  });
}

function renderAttackLog(snapshot) {
  const root = document.getElementById("attack-log");
  root.innerHTML = "";
  (snapshot.attack_log || []).forEach(item => {
    const div = document.createElement("div");
    div.className = "log-item";
    div.innerHTML = `
      <div><strong>${item.type}</strong> · ${item.result === "blocked" ? "已阻断" : "成功"}</div>
      <div class="muted">${formatTs(item.ts)} ${item.reason ? "· " + item.reason : ""} ${item.robot_id ? "· " + item.robot_id : ""} ${item.task_id ? "· " + item.task_id : ""}</div>
    `;
    root.appendChild(div);
  });
}

document.querySelectorAll(".danger-btn").forEach(btn => {
  btn.addEventListener("click", async () => {
    const attack = btn.dataset.attack;
    const site = document.getElementById("attack-site").value;
    const robotId = document.getElementById("attack-robot").value;
    if (attack === "unsigned_injection") {
      await postJSON("/api/attacks/unsigned_injection", {site, priority: 5, cargo_type: "medical"});
    } else if (attack === "replay") {
      await postJSON("/api/attacks/replay", {site});
    } else if (attack === "heartbeat_spoof") {
      await postJSON("/api/attacks/heartbeat_spoof", {robot_id: robotId});
    } else if (attack === "compromise") {
      await postJSON("/api/attacks/compromise", {robot_id: robotId});
    }
  });
});

function auditClass(item) {
  const dangerTitles = [
    "robot_revoked",
    "task_rejected",
    "spoof_blocked",
    "stale_completion_ignored",
    "duplicate_completion_ignored",
    "task_canceled_or_reclaimed"
  ];
  const warnTitles = [
    "battery_low_charge_dispatch",
    "robot_pause_changed",
    "robot_offline_changed"
  ];

  if (dangerTitles.includes(item.title) || item.level === "critical") return "audit-danger";
  if (warnTitles.includes(item.title) || item.level === "warn") return "audit-warn";
  if (item.level === "info") return "audit-info";
  return "";
}

function renderAudit(snapshot) {
  const root = document.getElementById("audit-stream");
  root.innerHTML = "";
  (snapshot.audit || []).forEach(item => {
    const div = document.createElement("div");
    div.className = "log-item " + auditClass(item);
    const levelText = item.level === "critical" ? "严重" : item.level === "warn" ? "告警" : "信息";
    div.innerHTML = `
      <div><strong>[${levelText}]</strong> ${auditTitleLabel(item.title)}</div>
      <div class="muted">${formatTs(item.ts)} · ${auditCategoryLabel(item.category)}</div>
      <pre>${JSON.stringify(item.details, null, 2)}</pre>
    `;
    root.appendChild(div);
  });
}

function renderMap(snapshot) {
  const canvas = document.getElementById("map-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const {width, height, obstacles, sites} = snapshot.map;
  const cellW = canvas.width / width;
  const cellH = canvas.height / height;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  for (let x = 0; x < width; x++) {
    for (let y = 0; y < height; y++) {
      ctx.fillStyle = (x + y) % 2 === 0 ? "rgba(255,255,255,0.03)" : "rgba(255,255,255,0.02)";
      ctx.fillRect(x * cellW, y * cellH, cellW - 1, cellH - 1);
    }
  }

  obstacles.forEach(([x, y]) => {
    ctx.fillStyle = "rgba(255, 107, 122, 0.26)";
    roundRect(ctx, x * cellW + 2, y * cellH + 2, cellW - 4, cellH - 4, 8, true, false);
  });

  Object.entries(sites).forEach(([name, point]) => {
    const [x, y] = point;
    ctx.fillStyle = "#4da3ff";
    roundRect(ctx, x * cellW + 3, y * cellH + 3, cellW - 6, cellH - 6, 10, true, false);
    ctx.fillStyle = "#eef3ff";
    ctx.font = "12px sans-serif";
    ctx.fillText(name, x * cellW + 4, y * cellH - 4);
  });

  (snapshot.tasks || []).forEach(task => {
    if (task.status === "completed") return;
    ctx.strokeStyle = task.priority >= 4 ? "#ffcc66" : "#78ffd6";
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.arc((task.x + 0.5) * cellW, (task.y + 0.5) * cellH, Math.min(cellW, cellH) / 3, 0, Math.PI * 2);
    ctx.stroke();
  });

  (snapshot.robots || []).forEach(robot => {
    ctx.fillStyle = robot.revoked ? "#ff6b7a" : robot.compromised ? "#ffcc66" : "#78ffd6";
    ctx.beginPath();
    ctx.arc((robot.x + 0.5) * cellW, (robot.y + 0.5) * cellH, Math.min(cellW, cellH) / 3, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = "#0b1020";
    ctx.font = "bold 12px sans-serif";
    ctx.fillText(robot.robot_id.replace("dog", "D"), (robot.x + 0.32) * cellW, (robot.y + 0.58) * cellH);

    if (robot.path && robot.path.length) {
      ctx.strokeStyle = "rgba(120,255,214,0.55)";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo((robot.x + 0.5) * cellW, (robot.y + 0.5) * cellH);
      robot.path.forEach(([px, py]) => ctx.lineTo((px + 0.5) * cellW, (py + 0.5) * cellH));
      ctx.stroke();
    }
  });
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function statusPill(status) {
  const cls = `status-pill status-${status}`;
  return `<span class="${cls}">${statusLabel(status)}</span>`;
}

function flags(robot) {
  const parts = [];
  if (robot.offline) parts.push("离线");
  if (robot.compromised) parts.push("失陷");
  if (robot.revoked) parts.push("已吊销");
  if (robot.paused) parts.push("已暂停");
  return parts.length ? parts.join(" · ") : "正常";
}

function formatTs(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function roundRect(ctx, x, y, w, h, r, fill, stroke) {
  if (w < 2 * r) r = w / 2;
  if (h < 2 * r) r = h / 2;
  ctx.beginPath();
  ctx.moveTo(x+r, y);
  ctx.arcTo(x+w, y,   x+w, y+h, r);
  ctx.arcTo(x+w, y+h, x,   y+h, r);
  ctx.arcTo(x,   y+h, x,   y,   r);
  ctx.arcTo(x,   y,   x+w, y,   r);
  ctx.closePath();
  if (fill) ctx.fill();
  if (stroke) ctx.stroke();
}
