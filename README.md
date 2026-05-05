# PuppySecOps Platform

PuppySecOps Platform 是一个面向 ROS2 机器人场景的信息安全演示平台。项目以“多机器人调度 + 安全协议防护 + 攻击仿真验证”为主线，用 Web 控制台展示机器人任务分配、路径规划、状态监控、攻击阻断、审计日志和安全策略变化。


## 项目亮点

- 多机器人任务调度与实时状态展示
- 基于网格地图的路径规划与任务执行模拟
- 自然语言任务解析，可接入 OpenAI 兼容接口、Claude 或 DeepSeek，也可回退到规则引擎
- RBAC 登录鉴权，区分管理员、操作员、安全审计员
- LBSE（Lease-Bound Secure Envelope）安全封装机制
- AES-GCM 加密认证、HKDF 派生密钥、AAD 绑定消息头
- `task_id`、`lease_id`、`session_id`、`seq`、`timestamp` 多维绑定，防止重放和越权完成任务
- 攻击实验台：未签名指令注入、重放攻击、心跳伪造、中间人篡改、DDoS 模拟、权限提升模拟、证书伪造模拟
- 审计日志、安全指标、证书吊销、异常检测和告警模块
- FastAPI + Jinja2 + WebSocket 实现前后端联动

## 系统架构

```text
puppy_secops_platform/
├── app/
│   ├── main.py                  # FastAPI 应用入口与 WebSocket 广播循环
│   ├── routes.py                # 页面路由、API 接口、攻击实验接口
│   ├── auth.py                  # 登录认证、Session、角色权限控制
│   ├── core/
│   │   ├── simulator.py         # 多机器人调度与安全仿真核心
│   │   ├── lbse.py              # LBSE 安全封装协议
│   │   ├── security.py          # HMAC 签名、防重放基础模块
│   │   ├── planner.py           # 网格路径规划
│   │   ├── models.py            # Robot、Task、PolicySet 等数据模型
│   │   ├── nl_agent.py          # 自然语言任务解析与 AI 接口适配
│   │   ├── access_controller.py # 访问控制
│   │   ├── certificate_manager.py
│   │   ├── key_manager.py
│   │   ├── audit_logger.py
│   │   ├── anomaly_detector.py
│   │   └── alert_system.py
│   ├── templates/               # HTML 页面模板
│   └── static/                  # 前端 JS/CSS 静态资源
├── config/
│   └── security_config_example.yaml
├── scripts/
│   ├── run.sh                   # Linux/macOS 启动脚本
│   └── populate_security_data.py
├── .env.example                 # 环境变量模板，不包含真实密钥
├── .gitignore
└── README.md
```

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/kelly123-ally/puppy_secops_platform.git
cd puppy_secops_platform
```

### 2. 创建虚拟环境

Linux / macOS：

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

如果项目目录下暂时没有 `requirements.txt`，可以先执行：

```bash
pip install fastapi uvicorn jinja2 python-multipart cryptography httpx pyyaml websockets pytest pytest-asyncio hypothesis pyotp qrcode pillow
pip freeze > requirements.txt
```

### 4. 配置环境变量

复制示例配置：

```bash
cp .env.example .env
```

Windows PowerShell：

```powershell
Copy-Item .env.example .env
```

然后在 `.env` 中按需填写：

```env
AI_PROVIDER=openai
AI_API_KEY=your_api_key_here
AI_BASE_URL=https://api.openai.com/v1
AI_MODEL=gpt-3.5-turbo
```

不配置 AI Key 也可以运行，系统会自动使用规则引擎解析任务。

### 5. 启动服务

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

或者使用脚本：

```bash
bash scripts/run.sh
```

浏览器打开：

```text
http://127.0.0.1:8000
```

## 演示账号

| 角色 | 用户名 | 密码 | 权限说明 |
| --- | --- | --- | --- |
| 管理员 | `admin` | `Admin123!` | 策略配置、机器人恢复、证书吊销、攻击实验 |
| 操作员 | `operator` | `Operator123!` | 创建任务、暂停机器人、查看任务状态 |
| 审计员 | `auditor` | `Auditor123!` | 查看审计日志和安全事件，执行部分安全验证实验 |

## 功能说明

### 机器人调度

系统内置多台 PuppyPi 机器人对象，支持任务创建、路径规划、任务分配、任务执行、完成回执、离线处理、暂停恢复和自动重分配。每个任务会绑定目标区域、优先级、货物类型和请求者信息。

### 自然语言任务解析

用户可以输入类似：

```text
请立即派一只机器狗给 A 区送急救药品
```

系统会解析出：

```json
{
  "site": "zone_a",
  "priority": 5,
  "cargo_type": "medical"
}
```

如果配置了 AI 接口，优先由模型解析；如果没有配置或接口失败，则自动回退到规则引擎。

### LBSE 安全封装

项目中的 LBSE 机制用于保护控制中心与机器人之间的关键消息，例如：

- `AssignTask`：控制中心向机器人下发任务
- `Heartbeat`：机器人向控制中心发送心跳
- `CompleteTask`：机器人向控制中心提交任务完成回执

LBSE 主要绑定字段包括：

- `msg_type`
- `sender_id`
- `receiver_id`
- `session_id`
- `seq`
- `timestamp_ms`
- `task_id`
- `lease_id`
- `role`
- `key_id`

这些字段作为 AES-GCM 的 AAD 参与认证，攻击者即使截获密文，也不能在不破坏认证标签的情况下修改任务、接收者、租约或序列号。

### 攻击实验台

当前支持的仿真攻击包括：

- 未签名任务注入
- 重放旧任务或旧回执
- 心跳伪造
- 中间人任务篡改
- DDoS 压力模拟
- 权限提升模拟
- 证书伪造模拟
- 机器人失陷与吊销

所有攻击均在本地仿真对象上完成，用于验证平台的防护链路，不会对外部主机发起真实攻击。

### 安全审计

平台会记录关键安全事件，例如：

- 平台启动
- LBSE 启用
- 策略修改
- 任务提交和完成
- 攻击阻断
- 机器人失陷
- 证书吊销
- 非法租约或重放序列号

审计信息可用于答辩时说明“攻击发生了什么、防护机制如何响应、系统最终如何恢复”。

## API 概览

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/api/login` | POST | 用户登录 |
| `/api/logout` | POST | 用户退出 |
| `/api/bootstrap` | GET | 获取初始化状态 |
| `/api/state` | GET | 获取实时状态快照 |
| `/api/audit` | GET | 获取审计日志 |
| `/api/tasks/natural` | POST | 提交自然语言任务 |
| `/api/tasks/structured` | POST | 提交结构化任务 |
| `/api/tasks/cancel` | POST | 取消任务 |
| `/api/policies/update` | POST | 更新安全策略 |
| `/api/robots/pause` | POST | 暂停或恢复机器人 |
| `/api/robots/offline` | POST | 设置机器人离线状态 |
| `/api/robots/recover` | POST | 恢复机器人 |
| `/api/robots/revoke` | POST | 吊销机器人 |
| `/api/attacks/unsigned_injection` | POST | 未签名任务注入实验 |
| `/api/attacks/replay` | POST | 重放攻击实验 |
| `/api/attacks/heartbeat_spoof` | POST | 心跳伪造实验 |
| `/api/attacks/compromise` | POST | 机器人失陷实验 |
| `/api/attacks/mitm` | POST | 中间人篡改实验 |
| `/api/attacks/ddos` | POST | DDoS 模拟实验 |
| `/api/attacks/privilege_escalation` | POST | 权限提升模拟实验 |
| `/api/attacks/cert_forge` | POST | 证书伪造模拟实验 |
| `/ws/stream` | WebSocket | 实时状态推送 |

## 测试

运行全部测试：

```bash
pytest
```

只运行核心安全模块测试：

```bash
pytest app/core
```

运行指定测试文件：

```bash
pytest app/core/test_key_manager_unit.py
```

## 上传 GitHub 前必须检查

不要提交以下内容：

- `.env`
- `.venv/`
- `__pycache__/`
- `.pytest_cache/`
- `.hypothesis/`
- `*.pem`
- `*.key`
- `*.bin`
- `audit_events.json`
- `crl.json`
- `threat_intelligence.json`
- 测试生成的临时日志和密钥文件

如果曾经把真实 API Key、私钥、证书或虚拟环境提交过，应该撤销密钥并清理 Git 历史后再公开仓库。

## 后续可接入真实 PuppyPi / ROS 的位置

当前项目是安全仿真平台。后续接入真实 PuppyPi 或 ROS 2 时，可以重点替换以下位置：

1. `app/core/simulator.py` 中的机器人运动逻辑，替换为真实机器人状态订阅与控制指令发布。
2. `app/core/planner.py` 中的网格路径规划，替换为 ROS 2 Nav2 action 或 PuppyPi 的运动控制接口。
3. `app/core/lbse.py` 中的消息封装逻辑，扩展为真实控制消息的加密认证层。
4. `app/core/access_controller.py` 与 `certificate_manager.py`，进一步对接 SROS2 enclave、证书、权限策略和 topic/service/action 访问控制。

## 项目声明
请勿将其中的攻击仿真思路用于未授权系统。项目中的默认账号、默认密码和演示密钥不应直接用于生产环境。
