# 🚀 AI接口快速开始

## 5分钟接入指南

### 步骤1: 安装依赖 (30秒)

```bash
pip install httpx
```

### 步骤2: 获取API密钥 (2分钟)

选择一个AI提供者并获取API密钥：

#### 选项A: OpenAI (推荐)
1. 访问 https://platform.openai.com/api-keys
2. 注册/登录账号
3. 点击 "Create new secret key"
4. 复制密钥（sk-开头）

#### 选项B: Claude
1. 访问 https://console.anthropic.com/
2. 注册/登录账号
3. 获取API密钥（sk-ant-开头）

#### 选项C: DeepSeek (国产)
1. 访问 https://platform.deepseek.com/
2. 注册/登录账号
3. 获取API密钥

### 步骤3: 配置环境变量 (1分钟)

#### Windows (PowerShell):
```powershell
$env:AI_PROVIDER="openai"
$env:AI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

#### Linux/Mac:
```bash
export AI_PROVIDER="openai"
export AI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

#### 或使用 .env 文件:
```bash
# 复制示例文件
cp .env.example .env

# 编辑文件
nano .env

# 填入配置
AI_PROVIDER=openai
AI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 步骤4: 测试 (1分钟)

```bash
# 运行测试脚本
python test_ai_integration.py
```

看到这个就成功了：
```
✅ AI提供者: OpenAIProvider
✅ 测试通过
```

### 步骤5: 启动应用 (30秒)

```bash
python -m uvicorn app.main:app --reload
```

看到这个就成功了：
```
✅ AI接口已启用: OpenAI (gpt-3.5-turbo)
```

## 立即体验

### 在Web界面测试

1. 打开浏览器访问 http://localhost:8000
2. 登录系统
3. 在任务创建界面输入自然语言：
   ```
   紧急！送医疗物资到B区
   ```
4. 系统会自动解析为：
   - 站点: zone_b
   - 优先级: 5 (紧急)
   - 货物: medical

### 测试更多例子

```
"需要尽快把急救药品送到A区域"
→ zone_a, 优先级4, medical

"帮我把文件送到C区吧，不着急"
→ zone_c, 优先级2, document

"立即派送维修工具到D区"
→ zone_d, 优先级5, repair
```

## 常见问题

### Q: 没有API密钥怎么办？
A: 系统会自动使用规则引擎，功能不受影响，只是解析能力有限。

### Q: API调用失败怎么办？
A: 系统会自动回退到规则引擎，不影响使用。

### Q: 成本高吗？
A: 非常低！单次解析约 $0.0003，1000次约 $0.30。

### Q: 响应慢吗？
A: GPT-3.5约1-3秒，Claude Haiku约0.5-2秒。

### Q: 支持中文吗？
A: 完全支持！AI对中文理解很好。

## 下一步

- 📚 阅读完整文档: `AI接口配置指南.md`
- 🔧 自定义配置: 编辑 `app/core/nl_agent.py`
- 📊 查看性能: 运行 `python test_ai_integration.py`
- 🎯 优化Prompt: 调整系统提示词

## 技术支持

遇到问题？
1. 查看 `AI接口配置指南.md`
2. 运行测试脚本诊断
3. 查看应用启动日志

---

**开始使用**: 5分钟，让您的系统拥有AI能力！🚀
