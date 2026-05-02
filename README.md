# PuppySecOps Platform

PuppySecOps Platform 是一套 **面向 ROS 2 / PuppyPi 多机器人系统的信息安全仿真平台**。  
它不是军事系统，而是用于 **园区配送 / 巡检 / 灾后补给** 等民用场景的安全验证与可视化演示。

## 功能概览

- 多机器人调度与路径规划（A*）
- 自然语言任务解析
- 任务租约（lease_id）与幂等完成控制
- 任务取消、重分配、离线/失陷隔离
- 电量模拟与自动回充
- HMAC 签名、nonce 防重放、命令验证
- RBAC 登录（管理员 / 操作员 / 审计员）
- 攻击回放实验台
- 审计日志、安全策略、证书/吊销状态可视化
- Web 控制面板（暗色风格，实时地图）

## 演示账号

- admin / Admin123!
- operator / Operator123!
- auditor / Auditor123!

## 运行方式

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
bash scripts/run.sh
```

浏览器打开：

```text
http://127.0.0.1:8000
```

## 主要目录

- `app/main.py`：FastAPI 入口
- `app/routes.py`：页面与 API 路由
- `app/auth.py`：登录与角色鉴权
- `app/core/simulator.py`：核心安全仿真引擎
- `app/core/planner.py`：A* 路径规划
- `app/core/security.py`：签名、防重放、策略引擎
- `app/templates/index.html`：控制台
- `app/static/app.js`：前端逻辑
- `app/static/styles.css`：前端样式

## 安全能力

### 1. 命令签名与防重放
任务创建通过后端签名，攻击实验室可以模拟：
- 未签名注入
- 重放旧 nonce
- 过期时间戳
- 心跳伪造

### 2. 多机器人一致性防护
- 每个任务分配生成 `lease_id`
- 完成消息只接受“当前有效租约”
- 旧租约完成会被忽略并记录审计日志
- 失陷或掉线触发自动回收与重分配

### 3. 最小权限与吊销
- 模拟证书状态与吊销表
- 机器人被标记为失陷后自动 revoke
- 被 revoke 的机器人无法继续接单

## 后续接 ROS 2 的位置

这套仿真平台为实机对接预留了两个位置：

1. `robot.step()` / `planner.path` 位置可以替换为 Nav2 action 调用
2. `security.py` 可以替换为真实 SROS2 / enclave / 访问控制策略

## 说明

这是作品赛/答辩用的**安全仿真平台**，攻击功能仅限本地仿真与防御验证，不用于真实网络入侵或破坏。
