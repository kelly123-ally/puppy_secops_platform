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
    
    const targetPanel = document.getElementById(`tab-${btn.dataset.tab}`);
    targetPanel.classList.add("active");
    
    // 添加淡入动画
    targetPanel.style.animation = 'none';
    setTimeout(() => {
      targetPanel.style.animation = 'slideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1) both';
    }, 10);
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
  const btn = e.target.querySelector('button[type="submit"]');
  
  // 禁用按钮防止重复提交
  btn.disabled = true;
  btn.textContent = '提交中...';
  
  await postJSON("/api/tasks/natural", Object.fromEntries(fd.entries()));
  
  // 恢复按钮
  btn.disabled = false;
  btn.textContent = '提交自然语言任务';
  e.target.reset();
});

// 优化：文本域自动调整高度
document.querySelectorAll('textarea').forEach(textarea => {
  // 自动调整高度
  textarea.addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.max(130, this.scrollHeight) + 'px';
  });
  
  // 添加焦点动画
  textarea.addEventListener('focus', function() {
    this.parentElement.classList.add('focused');
  });
  
  textarea.addEventListener('blur', function() {
    this.parentElement.classList.remove('focused');
  });
});

document.getElementById("task-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  payload.priority = Number(payload.priority);
  const btn = e.target.querySelector('button[type="submit"]');
  
  // 禁用按钮防止重复提交
  btn.disabled = true;
  btn.textContent = '提交中...';
  
  await postJSON("/api/tasks/structured", payload);
  
  // 恢复按钮
  btn.disabled = false;
  btn.textContent = '签名并下发任务';
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
    showNotification(`请求失败: ${text}`, 'error');
    return null;
  }
  showNotification('操作成功', 'success');
  return await resp.json();
}

// 优化4：通知系统 - 提供视觉反馈
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px;">
      <div style="font-size: 20px;">
        ${type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ'}
      </div>
      <div>
        <div style="font-weight: 700; margin-bottom: 4px;">
          ${type === 'success' ? '成功' : type === 'error' ? '错误' : '提示'}
        </div>
        <div style="font-size: 13px; color: var(--muted);">${message}</div>
      </div>
    </div>
  `;
  
  document.body.appendChild(notification);
  
  // 3秒后自动消失
  setTimeout(() => {
    notification.style.animation = 'slideOutRight 0.3s ease-out forwards';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
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
  renderSecurityMonitoring(snapshot);
}

// 渲染安全监控面板
function renderSecurityMonitoring(snapshot) {
  const metrics = snapshot.security_metrics || {};
  const robots = snapshot.robots || [];
  const attackLog = snapshot.attack_log || [];
  const audit = snapshot.audit || [];
  
  // 更新安全指标卡片
  setText('sec-blocked-attacks', 
    (metrics.blocked_injections || 0) + (metrics.blocked_replays || 0) + (metrics.blocked_spoofs || 0)
  );
  setText('sec-active-robots', robots.filter(r => !r.offline && !r.revoked).length);
  setText('sec-revoked-certs', (snapshot.revoked_certificates || []).length);
  setText('sec-anomalies', metrics.anomaly_detections || 0);
  setText('sec-auth-failures', metrics.auth_failures || 0);
  setText('sec-key-rotations', metrics.key_rotations || 0);
  
  // 渲染告警流
  renderSecurityAlerts(audit);
}

let lastSecurityAlertsData = null;

function renderSecurityAlerts(audit) {
  const alerts = audit.slice(-10).reverse(); // 最近10条，倒序显示
  const alertsKey = alerts.map(a => `${a.title}-${a.ts}`).join('|');
  
  if (lastSecurityAlertsData === alertsKey) return;
  lastSecurityAlertsData = alertsKey;
  
  const feed = document.getElementById('security-alert-feed');
  if (!feed) return;
  
  feed.innerHTML = '';
  
  if (alerts.length === 0) {
    feed.innerHTML = '<div class="alert-item info"><div class="alert-message">暂无告警信息</div></div>';
    return;
  }
  
  alerts.forEach(item => {
    const level = item.level === 'critical' ? 'critical' : item.level === 'warn' ? 'warning' : 'info';
    const div = document.createElement('div');
    div.className = `alert-item ${level}`;
    
    const levelText = item.level === 'critical' ? '严重' : item.level === 'warn' ? '告警' : '信息';
    const timeAgo = getTimeAgo(item.ts);
    
    div.innerHTML = `
      <div class="alert-header">
        <div class="alert-title">[${levelText}] ${auditTitleLabel(item.title)}</div>
        <div class="alert-time">${timeAgo}</div>
      </div>
      <div class="alert-message">${JSON.stringify(item.details).substring(0, 100)}...</div>
      <span class="alert-category">${auditCategoryLabel(item.category)}</span>
    `;
    
    feed.appendChild(div);
  });
}

function getTimeAgo(timestamp) {
  const now = Date.now() / 1000;
  const diff = now - timestamp;
  
  if (diff < 60) return '刚刚';
  if (diff < 3600) return `${Math.floor(diff / 60)}分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}小时前`;
  return `${Math.floor(diff / 86400)}天前`;
}

// 告警过滤按钮
document.addEventListener('DOMContentLoaded', () => {
  const filterBtns = document.querySelectorAll('.filter-btn');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      const level = btn.dataset.level;
      const alerts = document.querySelectorAll('.alert-item');
      
      alerts.forEach(alert => {
        if (level === 'all') {
          alert.style.display = 'block';
        } else {
          alert.style.display = alert.classList.contains(level) ? 'block' : 'none';
        }
      });
    });
  });
});

// 优化5：数值动画 - 让指标变化更流畅
let lastMetrics = { online: 0, running: 0, blocked: 0, revoked: 0 };

function renderMetrics(snapshot) {
  const robots = snapshot.robots || [];
  const tasks = snapshot.tasks || [];
  const metrics = snapshot.security_metrics || {};
  const online = robots.filter(r => !r.offline && !r.revoked).length;
  const running = tasks.filter(t => t.status === "assigned").length;
  const blocked = (metrics.blocked_injections || 0) + (metrics.blocked_replays || 0) + (metrics.blocked_spoofs || 0);
  const revoked = (snapshot.revoked_certificates || []).length;
  
  // 动画更新数值
  animateValue('m-online', lastMetrics.online, online);
  animateValue('m-running', lastMetrics.running, running);
  animateValue('m-blocked', lastMetrics.blocked, blocked);
  animateValue('m-revoked', lastMetrics.revoked, revoked);
  
  // 保存当前值
  lastMetrics = { online, running, blocked, revoked };
}

function animateValue(id, start, end) {
  const el = document.getElementById(id);
  if (!el) return;
  
  // 如果值没变，不需要动画
  if (start === end) {
    el.textContent = end;
    return;
  }
  
  // 添加脉冲效果
  el.classList.add('pulse');
  setTimeout(() => el.classList.remove('pulse'), 2000);
  
  const duration = 600; // 动画持续时间
  const startTime = Date.now();
  
  function update() {
    const now = Date.now();
    const progress = Math.min((now - startTime) / duration, 1);
    
    // 使用缓动函数
    const easeOutQuad = progress * (2 - progress);
    const current = Math.round(start + (end - start) * easeOutQuad);
    
    el.textContent = current;
    
    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }
  
  requestAnimationFrame(update);
}

let lastPoliciesData = null;

function renderPolicies(snapshot) {
  const policies = snapshot.policies || {};
  const policiesKey = JSON.stringify(policies);
  
  if (lastPoliciesData === policiesKey) return;
  lastPoliciesData = policiesKey;
  
  const root = document.getElementById("policy-summary");
  if (!root) return;
  
  root.innerHTML = "";
  Object.entries(policies).forEach(([key, value]) => {
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

let lastCertsData = null;

function renderCerts(snapshot) {
  const revoked = snapshot.revoked_certificates || [];
  const certsKey = revoked.join(',');
  
  if (lastCertsData === certsKey) return;
  lastCertsData = certsKey;
  
  const root = document.getElementById("cert-list");
  if (!root) return;
  
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

// 优化1：表格智能缓存 - 数据不变时不重绘
let lastRobotsData = null;
let lastTasksData = null;

function renderRobots(snapshot) {
  const robots = snapshot.robots || [];
  
  // 生成数据指纹，只包含会影响显示的字段
  const robotsKey = robots.map(r => 
    `${r.robot_id}-${r.status}-${Math.floor(r.battery)}-${r.x}-${r.y}-${r.current_task_id || ''}-${r.offline}-${r.compromised}-${r.revoked}-${r.paused}`
  ).join('|');
  
  // 如果数据没变，跳过重绘
  if (lastRobotsData === robotsKey) return;
  lastRobotsData = robotsKey;
  
  const root = document.getElementById("robot-table");
  if (!root) return;
  
  root.innerHTML = "";
  
  const head = document.createElement("div");
  head.className = "table-head table-row robot";
  head.innerHTML = `<div>机器人</div><div>状态</div><div>电量</div><div>位置</div><div>任务</div><div>租约</div>`;
  root.appendChild(head);

  robots.forEach(robot => {
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
  const tasks = snapshot.tasks || [];
  
  // 生成数据指纹
  const tasksKey = tasks.map(t => 
    `${t.task_id}-${t.status}-${t.assigned_robot || ''}-${t.site}-${t.priority}`
  ).join('|');
  
  // 如果数据没变，跳过重绘
  if (lastTasksData === tasksKey) return;
  lastTasksData = tasksKey;
  
  const root = document.getElementById("task-table");
  if (!root) return;
  
  root.innerHTML = "";
  
  const head = document.createElement("div");
  head.className = "table-head table-row task";
  head.innerHTML = `<div>任务</div><div>站点</div><div>优先级</div><div>状态</div><div>执行机器人</div><div>租约/操作</div>`;
  root.appendChild(head);

  tasks.forEach(task => {
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

let lastRobotControlsData = null;

function renderRobotControls(snapshot) {
  const robots = snapshot.robots || [];
  const controlsKey = robots.map(r => 
    `${r.robot_id}-${r.status}-${Math.floor(r.battery)}-${r.paused}-${r.offline}`
  ).join('|');
  
  if (lastRobotControlsData === controlsKey) return;
  lastRobotControlsData = controlsKey;
  
  const root = document.getElementById("robot-controls");
  if (!root) return;
  
  root.innerHTML = "";
  robots.forEach(robot => {
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
      const robot = robots.find(r => r.robot_id === robotId);
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

let lastSecurityMetricsData = null;

function renderSecurityMetrics(snapshot) {
  const metrics = snapshot.security_metrics || {};
  const metricsKey = JSON.stringify(metrics);
  
  if (lastSecurityMetricsData === metricsKey) return;
  lastSecurityMetricsData = metricsKey;
  
  const root = document.getElementById("security-metrics");
  if (!root) return;
  
  root.innerHTML = "";
  Object.entries(metrics).forEach(([key, value]) => {
    const row = document.createElement("div");
    row.className = "toggle-row";
    row.innerHTML = `<span>${key}</span><strong>${value}</strong>`;
    root.appendChild(row);
  });
}

let lastPolicyControlsData = null;

function renderPolicyControls(snapshot) {
  const policies = snapshot.policies || {};
  const user = state.currentUser || { role: "viewer" };
  const controlsKey = JSON.stringify(policies) + user.role;
  
  if (lastPolicyControlsData === controlsKey) return;
  lastPolicyControlsData = controlsKey;
  
  const root = document.getElementById("policy-controls");
  if (!root) return;
  
  root.innerHTML = "";

  Object.entries(policies).forEach(([key, value]) => {
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
    if (user.role !== "admin") return;
    sw.onclick = async () => {
      const key = sw.dataset.key;
      const current = sw.dataset.value === "true";
      await postJSON("/api/policies/update", { name: key, value: !current });
    };
  });
}

let lastAttackLogData = null;

function renderAttackLog(snapshot) {
  const logs = (snapshot.attack_log || []).slice(-20);
  const logKey = logs.map(item => `${item.type}-${item.result}-${item.ts}`).join('|');
  
  if (lastAttackLogData === logKey) return;
  lastAttackLogData = logKey;
  
  const root = document.getElementById("attack-log");
  if (!root) return;
  
  root.innerHTML = "";
  logs.forEach(item => {
    const div = document.createElement("div");
    div.className = "log-item";
    div.innerHTML = `
      <div><strong>${item.type}</strong> · ${item.result === "blocked" ? "已阻断" : "成功"}</div>
      <div class="muted">${formatTs(item.ts)} ${item.reason ? "· " + item.reason : ""} ${item.robot_id ? "· " + item.robot_id : ""} ${item.task_id ? "· " + item.task_id : ""}</div>
    `;
    root.appendChild(div);
  });
}

// 攻击统计
let attackStats = {
  total: 0,
  blocked: 0,
  succeeded: 0
};

document.querySelectorAll(".attack-btn").forEach(btn => {
  btn.addEventListener("click", async () => {
    const attack = btn.dataset.attack;
    const site = document.getElementById("attack-site").value;
    const robotId = document.getElementById("attack-robot").value;
    const intensity = document.getElementById("attack-intensity")?.value || "medium";
    
    // 视觉反馈：按钮震动效果
    btn.classList.add('attacking');
    setTimeout(() => btn.classList.remove('attacking'), 300);
    
    let result = null;
    let attackName = '';
    let attackResult = '';
    let blocked = false;
    
    if (attack === "unsigned_injection") {
      attackName = '未签名任务注入';
      result = await postJSON("/api/attacks/unsigned_injection", {site, priority: 5, cargo_type: "medical"});
      blocked = !result?.ok;
      attackResult = blocked ? '已阻断 - 缺少签名' : '攻击成功';
      addAttackResult(attackName, attackResult, blocked);
    } else if (attack === "replay") {
      attackName = '重放攻击';
      result = await postJSON("/api/attacks/replay", {site});
      blocked = !result?.ok;
      attackResult = blocked ? '已阻断 - 重复nonce' : '攻击成功';
      addAttackResult(attackName, attackResult, blocked);
    } else if (attack === "heartbeat_spoof") {
      attackName = '伪造心跳';
      result = await postJSON("/api/attacks/heartbeat_spoof", {robot_id: robotId});
      blocked = !result?.ok;
      attackResult = blocked ? '已阻断 - 无效LBSE' : '攻击成功';
      addAttackResult(attackName, attackResult, blocked);
    } else if (attack === "compromise") {
      attackName = '终端失陷';
      result = await postJSON("/api/attacks/compromise", {robot_id: robotId});
      blocked = !result?.ok;
      attackResult = result?.ok ? '攻击成功 - 终端已失陷' : '攻击失败';
      addAttackResult(attackName, attackResult, blocked);
    } else if (attack === "mitm") {
      attackName = '中间人攻击';
      result = await postJSON("/api/attacks/mitm", {robot_id: robotId, site: site});
      blocked = !result?.ok;
      attackResult = blocked ? '已阻断 - 通道加密' : '攻击成功';
      addAttackResult(attackName, attackResult, blocked);
    } else if (attack === "ddos") {
      attackName = 'DDoS攻击';
      result = await postJSON("/api/attacks/ddos", {target: "control_center", intensity: intensity});
      blocked = !result?.ok;
      attackResult = blocked ? '已阻断 - 速率限制' : '部分成功';
      addAttackResult(attackName, attackResult, blocked);
    } else if (attack === "privilege_escalation") {
      attackName = '权限提升攻击';
      result = await postJSON("/api/attacks/privilege_escalation", {robot_id: robotId, target_role: "admin"});
      blocked = !result?.ok;
      attackResult = blocked ? '已阻断 - 权限校验' : '攻击成功';
      addAttackResult(attackName, attackResult, blocked);
    } else if (attack === "cert_forge") {
      attackName = '证书伪造攻击';
      result = await postJSON("/api/attacks/cert_forge", {robot_id: robotId});
      blocked = !result?.ok;
      attackResult = blocked ? '已阻断 - 证书验证' : '攻击成功';
      addAttackResult(attackName, attackResult, blocked);
    }
  });
});

function addAttackResult(type, result, blocked) {
  const resultsList = document.getElementById('attack-log');
  if (!resultsList) return;
  
  const item = document.createElement('div');
  item.className = `attack-result-item ${blocked ? 'blocked' : 'succeeded'}`;
  
  const now = new Date();
  const timeStr = now.toLocaleTimeString();
  
  item.innerHTML = `
    <div class="attack-result-info">
      <div class="attack-result-type">${type}</div>
      <div class="attack-result-details">${timeStr} · ${result}</div>
    </div>
    <span class="attack-result-badge ${blocked ? 'blocked' : 'succeeded'}">
      ${blocked ? '已阻断' : '成功'}
    </span>
  `;
  
  resultsList.insertBefore(item, resultsList.firstChild);
  
  // 限制显示数量
  while (resultsList.children.length > 20) {
    resultsList.removeChild(resultsList.lastChild);
  }
  
  // 更新统计
  attackStats.total++;
  if (blocked) {
    attackStats.blocked++;
  } else {
    attackStats.succeeded++;
  }
  updateAttackStats();
}

function updateAttackStats() {
  setText('total-attacks', attackStats.total);
  setText('blocked-attacks', attackStats.blocked);
  setText('stat-total', attackStats.total);
  setText('stat-blocked', attackStats.blocked);
  setText('stat-succeeded', attackStats.succeeded);
  
  const blockRate = attackStats.total > 0 
    ? Math.round((attackStats.blocked / attackStats.total) * 100) 
    : 0;
  setText('block-rate', `${blockRate}%`);
  setText('stat-efficiency', `${blockRate}%`);
}

// 批量攻击测试
document.getElementById('batch-attack-btn')?.addEventListener('click', async () => {
  const count = parseInt(document.getElementById('attack-count').value) || 1;
  const btn = document.getElementById('batch-attack-btn');
  
  btn.disabled = true;
  btn.textContent = '攻击中...';
  
  for (let i = 0; i < count; i++) {
    // 随机选择攻击类型
    const attacks = ['unsigned_injection', 'replay', 'heartbeat_spoof', 'compromise'];
    const randomAttack = attacks[Math.floor(Math.random() * attacks.length)];
    
    const site = document.getElementById('attack-site').value;
    const robotId = document.getElementById('attack-robot').value;
    
    if (randomAttack === 'unsigned_injection') {
      await postJSON("/api/attacks/unsigned_injection", {site, priority: 5, cargo_type: "medical"});
    } else if (randomAttack === 'replay') {
      await postJSON("/api/attacks/replay", {site});
    } else if (randomAttack === 'heartbeat_spoof') {
      await postJSON("/api/attacks/heartbeat_spoof", {robot_id: robotId});
    } else if (randomAttack === 'compromise') {
      await postJSON("/api/attacks/compromise", {robot_id: robotId});
    }
    
    // 延迟避免过快
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  
  btn.disabled = false;
  btn.innerHTML = '<span class="btn-icon">🎯</span> 批量攻击测试';
  showNotification(`批量攻击测试完成（${count}次）`, 'success');
});

// 停止攻击
document.getElementById('stop-attack-btn')?.addEventListener('click', () => {
  showNotification('攻击已停止', 'info');
});

// 清空结果
document.getElementById('clear-results-btn')?.addEventListener('click', () => {
  const resultsList = document.getElementById('attack-log');
  if (resultsList) {
    resultsList.innerHTML = '';
  }
  attackStats = { total: 0, blocked: 0, succeeded: 0 };
  updateAttackStats();
  showNotification('攻击结果已清空', 'info');
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

let lastAuditData = null;

function renderAudit(snapshot) {
  const logs = (snapshot.audit || []).slice(-30);
  const auditKey = logs.map(item => `${item.title}-${item.ts}`).join('|');
  
  if (lastAuditData === auditKey) return;
  lastAuditData = auditKey;
  
  const root = document.getElementById("audit-stream");
  if (!root) return;
  
  root.innerHTML = "";
  logs.forEach(item => {
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

// 优化3：高性能地图渲染 - 移除复杂网格，使用简洁高级的视觉效果
let lastMapRender = 0;
const MAP_RENDER_THROTTLE = 100; // 限制地图渲染频率为100ms

// 动画状态
let animationFrame = 0;

function renderMap(snapshot) {
  const canvas = document.getElementById("map-canvas");
  if (!canvas) return;
  
  // 节流优化：避免过于频繁的地图重绘
  const now = Date.now();
  if (now - lastMapRender < MAP_RENDER_THROTTLE) return;
  lastMapRender = now;
  animationFrame++;
  
  const ctx = canvas.getContext("2d");
  const {width, height, obstacles, sites} = snapshot.map;
  const cellW = canvas.width / width;
  const cellH = canvas.height / height;

  // 清空画布，使用深色背景
  ctx.fillStyle = "#0a0e1a";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // 绘制简洁的网格线（仅边框，不填充每个格子）
  ctx.strokeStyle = "rgba(255,255,255,0.05)";
  ctx.lineWidth = 1;
  for (let x = 0; x <= width; x++) {
    ctx.beginPath();
    ctx.moveTo(x * cellW, 0);
    ctx.lineTo(x * cellW, canvas.height);
    ctx.stroke();
  }
  for (let y = 0; y <= height; y++) {
    ctx.beginPath();
    ctx.moveTo(0, y * cellH);
    ctx.lineTo(canvas.width, y * cellH);
    ctx.stroke();
  }

  // 障碍物 - 使用发光效果 + 阴影
  obstacles.forEach(([x, y]) => {
    const centerX = (x + 0.5) * cellW;
    const centerY = (y + 0.5) * cellH;
    const size = Math.min(cellW, cellH) * 0.4;
    
    // 多层外发光效果
    const gradient1 = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, size * 2);
    gradient1.addColorStop(0, "rgba(255, 107, 122, 0.3)");
    gradient1.addColorStop(0.5, "rgba(255, 107, 122, 0.15)");
    gradient1.addColorStop(1, "rgba(255, 107, 122, 0)");
    ctx.fillStyle = gradient1;
    ctx.fillRect(centerX - size * 2, centerY - size * 2, size * 4, size * 4);
    
    // 核心方块 + 阴影
    ctx.shadowColor = "rgba(255, 107, 122, 0.8)";
    ctx.shadowBlur = 15;
    ctx.fillStyle = "#ff6b7a";
    ctx.fillRect(centerX - size, centerY - size, size * 2, size * 2);
    ctx.shadowBlur = 0;
  });

  // 站点 - 使用蓝色发光效果 + 呼吸动画
  Object.entries(sites).forEach(([name, point]) => {
    const [x, y] = point;
    const centerX = (x + 0.5) * cellW;
    const centerY = (y + 0.5) * cellH;
    const size = Math.min(cellW, cellH) * 0.45;
    
    // 呼吸效果
    const breathe = Math.sin(animationFrame * 0.05) * 0.15 + 1;
    
    // 多层外发光
    const gradient1 = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, size * 2.5 * breathe);
    gradient1.addColorStop(0, "rgba(77, 163, 255, 0.4)");
    gradient1.addColorStop(0.5, "rgba(77, 163, 255, 0.2)");
    gradient1.addColorStop(1, "rgba(77, 163, 255, 0)");
    ctx.fillStyle = gradient1;
    ctx.fillRect(centerX - size * 2.5 * breathe, centerY - size * 2.5 * breathe, size * 5 * breathe, size * 5 * breathe);
    
    // 光环
    ctx.strokeStyle = `rgba(77, 163, 255, ${0.3 * breathe})`;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(centerX, centerY, size * 1.5 * breathe, 0, Math.PI * 2);
    ctx.stroke();
    
    // 核心圆形 + 阴影
    ctx.shadowColor = "rgba(77, 163, 255, 0.9)";
    ctx.shadowBlur = 20;
    ctx.fillStyle = "#4da3ff";
    ctx.beginPath();
    ctx.arc(centerX, centerY, size, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
    
    // 站点名称 + 发光文字
    ctx.shadowColor = "rgba(77, 163, 255, 0.8)";
    ctx.shadowBlur = 10;
    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 13px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(name, centerX, centerY - size - 8);
    ctx.shadowBlur = 0;
  });

  // 任务目标 - 脉动光环 + 优先级颜色
  (snapshot.tasks || []).forEach(task => {
    if (task.status === "completed") return;
    const centerX = (task.x + 0.5) * cellW;
    const centerY = (task.y + 0.5) * cellH;
    const radius = Math.min(cellW, cellH) * 0.35;
    
    // 脉动效果
    const pulse = Math.sin(animationFrame * 0.08) * 0.3 + 0.7;
    
    // 高优先级用橙色，普通用青色
    const isHighPriority = task.priority >= 4;
    const color = isHighPriority ? "255, 204, 102" : "120, 255, 214";
    
    // 外层光环
    ctx.strokeStyle = `rgba(${color}, ${pulse * 0.6})`;
    ctx.lineWidth = 4;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius * (1 + pulse * 0.3), 0, Math.PI * 2);
    ctx.stroke();
    
    // 内层光环
    ctx.strokeStyle = `rgba(${color}, ${pulse})`;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius * pulse, 0, Math.PI * 2);
    ctx.stroke();
  });

  // 机器人路径 - 渐变虚线轨迹
  (snapshot.robots || []).forEach(robot => {
    if (robot.path && robot.path.length) {
      ctx.setLineDash([8, 4]);
      
      // 绘制渐变路径
      for (let i = 0; i < robot.path.length - 1; i++) {
        const [x1, y1] = i === 0 ? [robot.x, robot.y] : robot.path[i - 1];
        const [x2, y2] = robot.path[i];
        
        const gradient = ctx.createLinearGradient(
          (x1 + 0.5) * cellW, (y1 + 0.5) * cellH,
          (x2 + 0.5) * cellW, (y2 + 0.5) * cellH
        );
        
        const alpha = 1 - (i / robot.path.length) * 0.6;
        gradient.addColorStop(0, `rgba(120, 255, 214, ${alpha * 0.6})`);
        gradient.addColorStop(1, `rgba(120, 255, 214, ${alpha * 0.3})`);
        
        ctx.strokeStyle = gradient;
        ctx.lineWidth = 3;
        ctx.beginPath();
        ctx.moveTo((x1 + 0.5) * cellW, (y1 + 0.5) * cellH);
        ctx.lineTo((x2 + 0.5) * cellW, (y2 + 0.5) * cellH);
        ctx.stroke();
      }
      
      ctx.setLineDash([]);
    }
  });

  // 机器人 - 发光圆形 + 状态指示 + 动态效果
  (snapshot.robots || []).forEach(robot => {
    const centerX = (robot.x + 0.5) * cellW;
    const centerY = (robot.y + 0.5) * cellH;
    const radius = Math.min(cellW, cellH) * 0.35;
    
    // 根据状态选择颜色
    let color = "#78ffd6"; // 正常
    let colorRgba = "rgba(120, 255, 214, 0.6)";
    let shadowColor = "rgba(120, 255, 214, 0.9)";
    
    if (robot.revoked) {
      color = "#ff6b7a"; // 已吊销
      colorRgba = "rgba(255, 107, 122, 0.6)";
      shadowColor = "rgba(255, 107, 122, 0.9)";
    } else if (robot.compromised) {
      color = "#ffcc66"; // 失陷
      colorRgba = "rgba(255, 204, 102, 0.6)";
      shadowColor = "rgba(255, 204, 102, 0.9)";
    } else if (robot.paused) {
      color = "#888888"; // 暂停
      colorRgba = "rgba(136, 136, 136, 0.6)";
      shadowColor = "rgba(136, 136, 136, 0.9)";
    }
    
    // 移动中的机器人添加尾迹效果
    if (robot.status === "enroute") {
      const trail = Math.sin(animationFrame * 0.1) * 0.5 + 0.5;
      const trailGradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, radius * 3);
      trailGradient.addColorStop(0, colorRgba);
      trailGradient.addColorStop(1, "rgba(0, 0, 0, 0)");
      ctx.fillStyle = trailGradient;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * (2 + trail), 0, Math.PI * 2);
      ctx.fill();
    }
    
    // 多层外发光
    const gradient1 = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, radius * 2.5);
    gradient1.addColorStop(0, colorRgba);
    gradient1.addColorStop(0.5, colorRgba.replace(/[\d.]+\)/, "0.3)"));
    gradient1.addColorStop(1, "rgba(0, 0, 0, 0)");
    ctx.fillStyle = gradient1;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius * 2.5, 0, Math.PI * 2);
    ctx.fill();
    
    // 核心圆形 + 强阴影
    ctx.shadowColor = shadowColor;
    ctx.shadowBlur = 25;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
    
    // 机器人ID
    ctx.fillStyle = "#0a0e1a";
    ctx.font = "bold 12px sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(robot.robot_id.replace("dog", "D"), centerX, centerY);
    
    // 电量指示条 - 增强版
    const barWidth = cellW * 0.6;
    const barHeight = 5;
    const barX = centerX - barWidth / 2;
    const barY = centerY + radius + 8;
    
    // 背景 + 边框
    ctx.fillStyle = "rgba(0, 0, 0, 0.5)";
    ctx.fillRect(barX - 1, barY - 1, barWidth + 2, barHeight + 2);
    ctx.fillStyle = "rgba(255, 255, 255, 0.15)";
    ctx.fillRect(barX, barY, barWidth, barHeight);
    
    // 电量渐变
    const batteryPercent = robot.battery / 100;
    const batteryWidth = barWidth * batteryPercent;
    
    let batteryGradient;
    if (robot.battery > 50) {
      batteryGradient = ctx.createLinearGradient(barX, barY, barX + batteryWidth, barY);
      batteryGradient.addColorStop(0, "#78ffd6");
      batteryGradient.addColorStop(1, "#4ce39a");
    } else if (robot.battery > 20) {
      batteryGradient = ctx.createLinearGradient(barX, barY, barX + batteryWidth, barY);
      batteryGradient.addColorStop(0, "#ffcc66");
      batteryGradient.addColorStop(1, "#ff8764");
    } else {
      batteryGradient = ctx.createLinearGradient(barX, barY, barX + batteryWidth, barY);
      batteryGradient.addColorStop(0, "#ff6b7a");
      batteryGradient.addColorStop(1, "#ff4757");
    }
    
    ctx.fillStyle = batteryGradient;
    ctx.fillRect(barX, barY, batteryWidth, barHeight);
    
    // 低电量闪烁效果
    if (robot.battery < 20) {
      const blink = Math.sin(animationFrame * 0.2) * 0.5 + 0.5;
      ctx.shadowColor = "rgba(255, 107, 122, 0.8)";
      ctx.shadowBlur = 10 * blink;
      ctx.fillRect(barX, barY, batteryWidth, barHeight);
      ctx.shadowBlur = 0;
    }
  });
}

// 地图点击事件处理
let mapTooltip = null;

function initMapInteraction() {
  const canvas = document.getElementById("map-canvas");
  if (!canvas) return;
  
  // 创建tooltip元素
  if (!mapTooltip) {
    mapTooltip = document.createElement('div');
    mapTooltip.id = 'map-tooltip';
    mapTooltip.className = 'map-tooltip';
    document.body.appendChild(mapTooltip);
  }
  
  canvas.addEventListener('click', (e) => {
    if (!state.snapshot) return;
    
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    const {width, height, sites} = state.snapshot.map;
    const cellW = canvas.width / width;
    const cellH = canvas.height / height;
    
    const gridX = Math.floor(x / cellW);
    const gridY = Math.floor(y / cellH);
    
    // 检查是否点击了机器人
    const clickedRobot = (state.snapshot.robots || []).find(robot => {
      return robot.x === gridX && robot.y === gridY;
    });
    
    if (clickedRobot) {
      showRobotTooltip(clickedRobot, e.clientX, e.clientY);
      return;
    }
    
    // 检查是否点击了站点
    for (const [siteName, [siteX, siteY]] of Object.entries(sites)) {
      if (siteX === gridX && siteY === gridY) {
        showSiteTooltip(siteName, [siteX, siteY], e.clientX, e.clientY);
        return;
      }
    }
    
    // 点击空白处关闭tooltip
    hideTooltip();
  });
  
  // 点击tooltip外部关闭
  document.addEventListener('click', (e) => {
    if (mapTooltip && !mapTooltip.contains(e.target) && e.target.id !== 'map-canvas') {
      hideTooltip();
    }
  });
}

function showRobotTooltip(robot, x, y) {
  if (!mapTooltip) return;
  
  // 查找该机器人的当前任务
  const currentTask = (state.snapshot.tasks || []).find(task => 
    task.assigned_to === robot.robot_id && task.status !== 'completed'
  );
  
  // 查找该机器人的历史任务
  const completedTasks = (state.snapshot.tasks || []).filter(task => 
    task.assigned_to === robot.robot_id && task.status === 'completed'
  ).slice(-3); // 最近3个
  
  let statusColor = '#78ffd6';
  let statusText = '正常运行';
  if (robot.revoked) {
    statusColor = '#ff6b7a';
    statusText = '已吊销';
  } else if (robot.compromised) {
    statusColor = '#ffcc66';
    statusText = '终端失陷';
  } else if (robot.paused) {
    statusColor = '#888888';
    statusText = '已暂停';
  } else if (robot.offline) {
    statusColor = '#888888';
    statusText = '离线';
  }
  
  const batteryColor = robot.battery > 50 ? '#4ce39a' : robot.battery > 20 ? '#ffcc66' : '#ff6b7a';
  
  mapTooltip.innerHTML = `
    <div class="tooltip-header">
      <div class="tooltip-title">
        <span class="tooltip-icon">🤖</span>
        <span>${robot.robot_id.toUpperCase()}</span>
      </div>
      <button class="tooltip-close" onclick="hideTooltip()">✕</button>
    </div>
    
    <div class="tooltip-section">
      <div class="tooltip-row">
        <span class="tooltip-label">状态</span>
        <span class="tooltip-value" style="color: ${statusColor}">${statusText}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">电量</span>
        <span class="tooltip-value" style="color: ${batteryColor}">${robot.battery}%</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">位置</span>
        <span class="tooltip-value">(${robot.x}, ${robot.y})</span>
      </div>
    </div>
    
    ${currentTask ? `
      <div class="tooltip-section">
        <div class="tooltip-section-title">📋 当前任务</div>
        <div class="task-card">
          <div class="task-card-header">
            <span class="task-id">${currentTask.task_id}</span>
            <span class="task-priority priority-${currentTask.priority >= 4 ? 'high' : 'normal'}">
              P${currentTask.priority}
            </span>
          </div>
          <div class="task-card-body">
            <div class="task-info">
              <span class="task-label">目标</span>
              <span class="task-value">(${currentTask.x}, ${currentTask.y})</span>
            </div>
            <div class="task-info">
              <span class="task-label">货物</span>
              <span class="task-value">${currentTask.cargo_type || 'N/A'}</span>
            </div>
            <div class="task-info">
              <span class="task-label">状态</span>
              <span class="task-value">${statusLabel(currentTask.status)}</span>
            </div>
          </div>
        </div>
      </div>
    ` : '<div class="tooltip-section"><div class="tooltip-empty">暂无任务</div></div>'}
    
    ${completedTasks.length > 0 ? `
      <div class="tooltip-section">
        <div class="tooltip-section-title">✅ 最近完成 (${completedTasks.length})</div>
        ${completedTasks.map(task => `
          <div class="task-mini">
            <span class="task-mini-id">${task.task_id}</span>
            <span class="task-mini-cargo">${task.cargo_type || 'N/A'}</span>
          </div>
        `).join('')}
      </div>
    ` : ''}
  `;
  
  positionTooltip(x, y);
  mapTooltip.classList.add('visible');
}

function showSiteTooltip(siteName, [siteX, siteY], x, y) {
  if (!mapTooltip) return;
  
  // 查找该站点的任务
  const siteTasks = (state.snapshot.tasks || []).filter(task => 
    task.x === siteX && task.y === siteY
  );
  
  const pendingTasks = siteTasks.filter(t => t.status === 'queued' || t.status === 'assigned');
  const enrouteTasks = siteTasks.filter(t => t.status === 'enroute');
  const completedTasks = siteTasks.filter(t => t.status === 'completed').slice(-5);
  
  mapTooltip.innerHTML = `
    <div class="tooltip-header">
      <div class="tooltip-title">
        <span class="tooltip-icon">📍</span>
        <span>${siteName.toUpperCase()}</span>
      </div>
      <button class="tooltip-close" onclick="hideTooltip()">✕</button>
    </div>
    
    <div class="tooltip-section">
      <div class="tooltip-row">
        <span class="tooltip-label">位置</span>
        <span class="tooltip-value">(${siteX}, ${siteY})</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">任务总数</span>
        <span class="tooltip-value">${siteTasks.length}</span>
      </div>
    </div>
    
    ${pendingTasks.length > 0 ? `
      <div class="tooltip-section">
        <div class="tooltip-section-title">⏳ 等待中 (${pendingTasks.length})</div>
        ${pendingTasks.slice(0, 3).map(task => `
          <div class="task-card">
            <div class="task-card-header">
              <span class="task-id">${task.task_id}</span>
              <span class="task-priority priority-${task.priority >= 4 ? 'high' : 'normal'}">
                P${task.priority}
              </span>
            </div>
            <div class="task-card-body">
              <div class="task-info">
                <span class="task-label">货物</span>
                <span class="task-value">${task.cargo_type || 'N/A'}</span>
              </div>
              <div class="task-info">
                <span class="task-label">状态</span>
                <span class="task-value">${statusLabel(task.status)}</span>
              </div>
            </div>
          </div>
        `).join('')}
        ${pendingTasks.length > 3 ? `<div class="tooltip-more">还有 ${pendingTasks.length - 3} 个任务...</div>` : ''}
      </div>
    ` : ''}
    
    ${enrouteTasks.length > 0 ? `
      <div class="tooltip-section">
        <div class="tooltip-section-title">🚚 配送中 (${enrouteTasks.length})</div>
        ${enrouteTasks.map(task => `
          <div class="task-mini">
            <span class="task-mini-id">${task.task_id}</span>
            <span class="task-mini-robot">→ ${task.assigned_to || 'N/A'}</span>
          </div>
        `).join('')}
      </div>
    ` : ''}
    
    ${completedTasks.length > 0 ? `
      <div class="tooltip-section">
        <div class="tooltip-section-title">✅ 已完成 (${completedTasks.length})</div>
        ${completedTasks.slice(0, 3).map(task => `
          <div class="task-mini">
            <span class="task-mini-id">${task.task_id}</span>
            <span class="task-mini-cargo">${task.cargo_type || 'N/A'}</span>
          </div>
        `).join('')}
      </div>
    ` : ''}
    
    ${siteTasks.length === 0 ? '<div class="tooltip-section"><div class="tooltip-empty">暂无任务</div></div>' : ''}
  `;
  
  positionTooltip(x, y);
  mapTooltip.classList.add('visible');
}

function positionTooltip(x, y) {
  if (!mapTooltip) return;
  
  const tooltipRect = mapTooltip.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  
  let left = x + 15;
  let top = y + 15;
  
  // 防止超出右边界
  if (left + tooltipRect.width > viewportWidth - 20) {
    left = x - tooltipRect.width - 15;
  }
  
  // 防止超出底部边界
  if (top + tooltipRect.height > viewportHeight - 20) {
    top = y - tooltipRect.height - 15;
  }
  
  // 防止超出左边界
  if (left < 20) {
    left = 20;
  }
  
  // 防止超出顶部边界
  if (top < 20) {
    top = 20;
  }
  
  mapTooltip.style.left = left + 'px';
  mapTooltip.style.top = top + 'px';
}

function hideTooltip() {
  if (mapTooltip) {
    mapTooltip.classList.remove('visible');
  }
}

// 初始化地图交互
document.addEventListener('DOMContentLoaded', () => {
  initMapInteraction();
});

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
