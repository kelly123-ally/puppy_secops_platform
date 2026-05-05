# 🤖 AI接口使用说明

## 一句话总结

**您的系统现在支持使用OpenAI、Claude、DeepSeek等AI模型来智能解析自然语言任务！**

## 快速开始（3步）

### 1️⃣ 安装依赖
```bash
pip install httpx
```

### 2️⃣ 配置API密钥
```bash
# Windows
$env:AI_PROVIDER="openai"
$env:AI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Linux/Mac
export AI_PROVIDER="openai"
export AI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### 3️⃣ 启动应用
```bash
python -m uvicorn app.main:app --reload
```

看到这个就成功了：
```
✅ AI接口已启用: OpenAI (gpt-3.5-turbo)
```

## 效果对比

### 之前（规则引擎）
```
输入: "送药到B区"
✅ 能理解

输入: "需要尽快把急救药品送到A区域，这个很重要"
❌ 理解有限
```

### 现在（AI增强）
```
输入: "送药到B区"
✅ 完美理解

输入: "需要尽快把急救药品送到A区域，这个很重要"
✅ 完美理解！
  - 站点: zone_a
  - 优先级: 4 (尽快+重要)
  - 货物: medical (急救药品)
```

## 支持的AI

| AI | 获取密钥 | 成本 |
|----|---------|------|
| OpenAI | https://platform.openai.com/api-keys | $0.0003/次 |
| Claude | https://console.anthropic.com/ | $0.00015/次 |
| DeepSeek | https://platform.deepseek.com/ | ¥0.0003/次 |

## 配置示例

### OpenAI
```bash
AI_PROVIDER=openai
AI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AI_MODEL=gpt-3.5-turbo
```

### Claude
```bash
AI_PROVIDER=claude
AI_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AI_MODEL=claude-3-haiku-20240307
```

### DeepSeek
```bash
AI_PROVIDER=deepseek
AI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## 测试

```bash
# 运行测试脚本
python test_ai_integration.py
```

## 不配置会怎样？

**完全没问题！** 系统会自动使用规则引擎，功能正常，只是解析能力有限。

## 成本

- 单次解析: $0.0003 (约0.002元)
- 每天100次: $0.03 (约0.2元)
- 每月3000次: $0.90 (约6元)

**结论**: 成本极低！

## 详细文档

- 📚 **完整配置**: `AI接口配置指南.md`
- 🚀 **快速开始**: `AI接口快速开始.md`
- 📊 **技术总结**: `AI接口集成总结.md`
- ⚙️ **配置模板**: `.env.example`

## 常见问题

**Q: 必须配置吗？**
A: 不必须，不配置也能正常使用。

**Q: 成本高吗？**
A: 非常低，每月几元钱。

**Q: 响应慢吗？**
A: 1-3秒，可接受。

**Q: 支持中文吗？**
A: 完全支持！

**Q: 会失败吗？**
A: 失败会自动回退到规则引擎，不影响使用。

## 立即体验

1. 配置API密钥
2. 启动应用
3. 输入自然语言任务：
   ```
   "紧急！送医疗物资到B区"
   "需要尽快把急救药品送到A区域"
   "帮我把文件送到C区吧，不着急"
   ```
4. 看AI如何智能理解！

---

**开始使用**: 3步配置，让您的系统拥有AI能力！🚀
