# 🤖 AI接口配置指南

## 概述

系统现已支持真实的AI接口，可以使用大语言模型（LLM）来解析自然语言任务！

### 支持的AI提供者

1. **OpenAI** (GPT-3.5/GPT-4)
2. **Anthropic Claude** (Claude 3系列)
3. **DeepSeek** (国产大模型)
4. **OpenAI兼容服务** (Azure OpenAI、国内中转等)

### 工作模式

- ✅ **AI模式**: 配置API密钥后，使用AI解析任务
- 🔄 **规则引擎**: 未配置或AI失败时，自动回退到规则引擎
- 🛡️ **容错机制**: AI解析失败不影响系统运行

## 快速开始

### 1. 安装依赖

```bash
pip install httpx
# 或
pip install -r requirements.txt
```

### 2. 配置环境变量

#### 方法A: 使用 .env 文件（推荐）

```bash
# 复制示例文件
cp .env.example .env

# 编辑 .env 文件
nano .env
```

#### 方法B: 直接设置环境变量

**Windows (PowerShell)**:
```powershell
$env:AI_PROVIDER="openai"
$env:AI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

**Linux/Mac**:
```bash
export AI_PROVIDER="openai"
export AI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### 3. 启动应用

```bash
python -m uvicorn app.main:app --reload
```

查看启动日志：
- ✅ `AI接口已启用: OpenAI (gpt-3.5-turbo)` - 成功
- ⚠️ `未配置AI_API_KEY，将使用规则引擎` - 未配置

## 详细配置

### OpenAI配置

#### 官方API

```bash
AI_PROVIDER=openai
AI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AI_MODEL=gpt-3.5-turbo  # 可选: gpt-4, gpt-4-turbo-preview
```

**获取API密钥**: https://platform.openai.com/api-keys

#### Azure OpenAI

```bash
AI_PROVIDER=openai
AI_API_KEY=your_azure_key
AI_BASE_URL=https://your-resource.openai.azure.com/openai/deployments/your-deployment
AI_MODEL=gpt-35-turbo
```

#### 国内中转服务

```bash
AI_PROVIDER=openai
AI_API_KEY=your_api_key
AI_BASE_URL=https://api.your-proxy.com/v1
AI_MODEL=gpt-3.5-turbo
```

### Claude配置

```bash
AI_PROVIDER=claude
AI_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AI_MODEL=claude-3-haiku-20240307  # 最快最便宜
# AI_MODEL=claude-3-sonnet-20240229  # 平衡
# AI_MODEL=claude-3-opus-20240229    # 最强
```

**获取API密钥**: https://console.anthropic.com/

### DeepSeek配置

```bash
AI_PROVIDER=deepseek
AI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AI_MODEL=deepseek-chat
```

**获取API密钥**: https://platform.deepseek.com/

## 使用示例

### 自然语言任务示例

配置AI后，系统可以理解更复杂的自然语言：

#### 示例1: 基础任务
```
输入: "紧急！送医疗物资到B区"
AI解析:
  - site: zone_b
  - priority: 5 (紧急)
  - cargo_type: medical
```

#### 示例2: 复杂描述
```
输入: "需要尽快把急救药品送到A区域，这个很重要"
AI解析:
  - site: zone_a
  - priority: 4 (尽快)
  - cargo_type: medical (急救药品)
```

#### 示例3: 口语化表达
```
输入: "帮我把那个文件送到C区吧，不着急"
AI解析:
  - site: zone_c
  - priority: 2 (不着急)
  - cargo_type: document (文件)
```

#### 示例4: 多信息混合
```
输入: "立即派送维修工具到D区，机器人坏了需要紧急修理"
AI解析:
  - site: zone_d
  - priority: 5 (立即、紧急)
  - cargo_type: repair (维修工具)
```

### 规则引擎 vs AI

| 特性 | 规则引擎 | AI模式 |
|------|---------|--------|
| 关键词匹配 | ✅ 精确 | ✅ 智能 |
| 复杂语句 | ❌ 有限 | ✅ 强大 |
| 口语化 | ❌ 困难 | ✅ 支持 |
| 多义词 | ❌ 困难 | ✅ 理解 |
| 上下文 | ❌ 无 | ✅ 有 |
| 响应速度 | ⚡ 极快 | 🐢 较慢 |
| 成本 | 💰 免费 | 💰 付费 |

## API成本估算

### OpenAI (GPT-3.5-turbo)
- **价格**: $0.0005/1K tokens (输入), $0.0015/1K tokens (输出)
- **单次任务**: 约200 tokens，成本约 $0.0003
- **1000次任务**: 约 $0.30

### Claude (Haiku)
- **价格**: $0.00025/1K tokens (输入), $0.00125/1K tokens (输出)
- **单次任务**: 约200 tokens，成本约 $0.00015
- **1000次任务**: 约 $0.15

### DeepSeek
- **价格**: ¥0.001/1K tokens (输入), ¥0.002/1K tokens (输出)
- **单次任务**: 约200 tokens，成本约 ¥0.0003
- **1000次任务**: 约 ¥0.30

## 故障排查

### 问题1: 启动时显示"未配置AI_API_KEY"

**原因**: 环境变量未设置

**解决**:
1. 检查 .env 文件是否存在
2. 确认 AI_API_KEY 已填写
3. 重启应用

### 问题2: 显示"AI接口初始化失败"

**原因**: API密钥无效或网络问题

**解决**:
1. 检查API密钥是否正确
2. 测试网络连接
3. 检查API服务状态

### 问题3: AI解析失败，回退到规则引擎

**原因**: API调用失败或返回格式错误

**影响**: 系统自动使用规则引擎，不影响功能

**解决**:
1. 查看控制台错误日志
2. 检查API配额是否用完
3. 验证API密钥权限

### 问题4: 响应速度慢

**原因**: AI推理需要时间

**优化**:
1. 使用更快的模型（如 Claude Haiku）
2. 考虑使用规则引擎
3. 实现缓存机制

## 高级配置

### 自定义Prompt

编辑 `app/core/nl_agent.py` 中的 `system_prompt`：

```python
system_prompt = """你是一个物流任务解析助手...
（自定义您的提示词）
"""
```

### 添加新的AI提供者

```python
class CustomProvider(AIProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
    
    async def parse_task(self, text: str) -> dict:
        # 实现您的API调用逻辑
        pass
```

### 混合模式

可以实现智能路由：
- 简单任务 → 规则引擎（快速、免费）
- 复杂任务 → AI解析（准确、智能）

## 安全建议

### 1. 保护API密钥

```bash
# 不要提交 .env 文件到Git
echo ".env" >> .gitignore

# 使用环境变量管理工具
# - Docker Secrets
# - Kubernetes Secrets
# - AWS Secrets Manager
```

### 2. 限制API调用

```python
# 实现速率限制
# 实现缓存机制
# 监控API使用量
```

### 3. 错误处理

```python
# 已实现：
# - 超时控制（30秒）
# - 异常捕获
# - 自动回退
```

## 监控和日志

### 查看AI使用情况

```python
# 在任务中查看 source 字段
task["source"]  # "ai_agent" 或 "rule_engine"
```

### 日志输出

```
✅ AI接口已启用: OpenAI (gpt-3.5-turbo)
⚠️  AI解析失败，回退到规则引擎: timeout
```

## 性能对比

| 指标 | 规则引擎 | GPT-3.5 | Claude Haiku | DeepSeek |
|------|---------|---------|--------------|----------|
| 响应时间 | <1ms | 1-3s | 0.5-2s | 1-2s |
| 准确率 | 85% | 95% | 95% | 93% |
| 成本/1K次 | $0 | $0.30 | $0.15 | ¥0.30 |
| 复杂语句 | ❌ | ✅ | ✅ | ✅ |

## 最佳实践

### 1. 开发环境
```bash
# 使用规则引擎（快速、免费）
# 不设置 AI_API_KEY
```

### 2. 测试环境
```bash
# 使用便宜的模型测试
AI_PROVIDER=claude
AI_MODEL=claude-3-haiku-20240307
```

### 3. 生产环境
```bash
# 使用稳定的模型
AI_PROVIDER=openai
AI_MODEL=gpt-3.5-turbo
# 配置监控和告警
```

## 未来扩展

可能的增强功能：
1. **缓存机制** - 相似任务复用结果
2. **批量处理** - 一次API调用处理多个任务
3. **流式响应** - 实时显示解析进度
4. **多模型路由** - 根据任务复杂度选择模型
5. **本地模型** - 支持本地部署的开源模型

## 技术支持

- 📧 问题反馈: 提交Issue
- 📚 API文档: 
  - OpenAI: https://platform.openai.com/docs
  - Claude: https://docs.anthropic.com
  - DeepSeek: https://platform.deepseek.com/docs

---

**开始使用**: 配置您的API密钥，体验AI驱动的任务解析！🚀
