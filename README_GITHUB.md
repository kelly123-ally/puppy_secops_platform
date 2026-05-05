# 🤖 多机器人安全验证面板

一个功能完整的多机器人物流系统安全验证平台，具有实时监控、攻击模拟、AI任务解析等功能。

## ✨ 主要特性

### 🎯 核心功能
- **实时任务态势图** - 可视化地图显示机器人位置、任务和路径
- **安全监控中心** - 实时监控系统安全状态
- **攻击实验室** - 8种攻击类型模拟测试
- **证书管理** - 完整的PKI证书管理系统
- **审计日志** - 完整的操作审计追踪

### 🎨 视觉增强
- **动态地图** - 呼吸动画、脉动光环、移动尾迹
- **交互对话框** - 点击机器人/站点查看详细信息
- **实时指示器** - LIVE状态、动态光效
- **美观界面** - 毛玻璃效果、发光边框、流畅动画

### 🤖 AI集成
- **多AI提供者** - 支持OpenAI、Claude、DeepSeek、通义千问
- **智能解析** - 自然语言任务解析
- **自动回退** - AI失败自动使用规则引擎

### 🔒 安全特性
- **TLS加密** - 完整的TLS通信加密
- **证书管理** - 自动签发、吊销、轮换
- **MFA认证** - 多因素身份验证
- **攻击防护** - 8种攻击类型防护

## 🚀 快速开始

### 1. 克隆项目
```bash
git clone <your-repo-url>
cd puppy_secops_platform
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 配置（可选）
```bash
# 复制配置模板
cp .env.example .env

# 编辑配置文件
nano .env
```

### 4. 启动应用
```bash
python -m uvicorn app.main:app --reload
```

### 5. 访问
打开浏览器访问: http://localhost:8000

默认账号:
- 用户名: `admin`
- 密码: `admin123`

## 📚 文档

### 快速指南
- `README_AI.md` - AI接口使用说明
- `AI接口快速开始.md` - 5分钟快速配置
- `快速体验指南.md` - 功能体验指南

### 详细文档
- `AI接口配置指南.md` - 完整AI配置
- `地图交互功能说明.md` - 交互功能详解
- `地图增强效果说明.md` - 视觉效果说明

### 技术文档
- `AI接口集成总结.md` - AI集成技术总结
- `INTERACTIVE_MAP_SUMMARY.md` - 交互功能技术总结
- `MAP_ENHANCEMENT_SUMMARY.md` - 地图增强技术总结

## 🎯 功能演示

### 地图交互
```
点击机器人 → 查看状态、电量、当前任务
点击站点   → 查看任务队列、配送状态
点击空白   → 关闭对话框
```

### AI任务解析
```
输入: "紧急！送医疗物资到B区"
AI解析:
  - 站点: zone_b
  - 优先级: 5 (紧急)
  - 货物: medical
```

### 攻击模拟
- 🚫 未签名任务注入
- 🔄 重放攻击
- 💓 伪造心跳
- 🦠 终端失陷
- 🕵️ 中间人攻击
- 💥 DDoS攻击
- 👑 权限提升
- 🎭 证书伪造

## 🛠️ 技术栈

### 后端
- **FastAPI** - 现代Web框架
- **Python 3.11+** - 编程语言
- **Cryptography** - 加密库
- **PyYAML** - 配置解析

### 前端
- **原生JavaScript** - 无框架依赖
- **Canvas API** - 地图渲染
- **WebSocket** - 实时通信
- **CSS3** - 现代样式

### AI集成
- **httpx** - HTTP客户端
- **OpenAI API** - GPT模型
- **Claude API** - Anthropic模型
- **通义千问** - 阿里云模型

## 📊 项目结构

```
puppy_secops_platform/
├── app/
│   ├── core/              # 核心业务逻辑
│   │   ├── nl_agent.py    # AI任务解析
│   │   ├── simulator.py   # 系统模拟器
│   │   ├── certificate_manager.py
│   │   └── ...
│   ├── static/            # 静态资源
│   │   ├── app.js         # 前端逻辑
│   │   └── styles.css     # 样式文件
│   ├── templates/         # HTML模板
│   ├── main.py            # 应用入口
│   └── routes.py          # 路由定义
├── config/                # 配置文件
├── scripts/               # 工具脚本
├── .env.example           # 配置模板
├── requirements.txt       # Python依赖
└── README.md              # 项目说明
```

## 🔧 配置说明

### AI配置（可选）

支持多种AI提供者：

#### OpenAI
```bash
AI_PROVIDER=openai
AI_API_KEY=sk-xxx
AI_MODEL=gpt-3.5-turbo
```

#### Claude
```bash
AI_PROVIDER=claude
AI_API_KEY=sk-ant-xxx
AI_MODEL=claude-3-haiku-20240307
```

#### 通义千问
```bash
AI_PROVIDER=openai
AI_API_KEY=sk-xxx
AI_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
AI_MODEL=qwen-turbo
```

### 不配置AI
系统会自动使用规则引擎，功能完全正常。

## 🧪 测试

```bash
# 运行所有测试
pytest -v

# 测试AI集成
python test_ai_integration.py

# 测试特定模块
pytest app/core/test_certificate_manager_unit.py -v
```

## 📈 性能

- **地图渲染**: 60fps流畅动画
- **API响应**: <100ms
- **AI解析**: 1-3秒
- **WebSocket**: 实时更新

## 🔒 安全性

- ✅ TLS加密通信
- ✅ 证书双向认证
- ✅ MFA多因素认证
- ✅ 完整审计日志
- ✅ 攻击检测防护

## 💰 成本

### AI使用成本（可选）
- GPT-3.5: $0.0003/次
- Claude Haiku: $0.00015/次
- 通义千问: ¥0.00018/次

每月3000次任务约 $0.90 - $1.00

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📄 许可证

MIT License

## 📞 支持

- 📧 Issues: 提交GitHub Issue
- 📚 文档: 查看项目文档
- 💬 讨论: GitHub Discussions

## 🎉 致谢

感谢所有贡献者和使用者！

---

**开始使用**: 克隆项目，安装依赖，启动应用！🚀
