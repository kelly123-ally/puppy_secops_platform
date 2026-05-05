# 📤 GitHub上传指南

## 🚨 重要提醒

**在上传前，请确保已经删除或忽略了敏感信息！**

## ✅ 已配置的保护

### .gitignore 已配置
以下文件/文件夹将被自动忽略：

#### 敏感文件
- ✅ `.env` - API密钥配置
- ✅ `*.pem` - 证书和密钥文件
- ✅ `*.key` - 密钥文件
- ✅ `*.bin` - 二进制密钥
- ✅ `audit_events.json` - 审计日志
- ✅ `ca_cert.pem`, `ca_key.pem` - CA证书
- ✅ `master_key.bin` - 主密钥

#### 临时文件
- ✅ `__pycache__/` - Python缓存
- ✅ `.vscode/` - IDE配置
- ✅ `.kiro/` - Kiro配置
- ✅ `.hypothesis/` - 测试数据
- ✅ `*.backup` - 备份文件

## 📋 上传步骤

### 方法1: 使用Git命令行

#### 1. 初始化（如果还没有）
```bash
git init
```

#### 2. 添加远程仓库
```bash
# 替换为您的GitHub仓库地址
git remote add origin https://github.com/your-username/your-repo.git
```

#### 3. 检查状态
```bash
git status
```

#### 4. 添加文件
```bash
# 添加所有文件（.gitignore会自动过滤敏感文件）
git add .

# 或者选择性添加
git add app/
git add requirements.txt
git add README_GITHUB.md
git add .env.example
```

#### 5. 提交
```bash
git commit -m "Initial commit: Multi-robot security platform with AI integration"
```

#### 6. 推送
```bash
# 首次推送
git push -u origin master

# 或者推送到main分支
git branch -M main
git push -u origin main
```

### 方法2: 使用GitHub Desktop

1. 打开GitHub Desktop
2. 选择 "Add Local Repository"
3. 选择项目文件夹
4. 查看变更列表
5. 填写提交信息
6. 点击 "Commit to master"
7. 点击 "Push origin"

### 方法3: 使用VS Code

1. 打开VS Code
2. 打开源代码管理面板（Ctrl+Shift+G）
3. 查看变更列表
4. 点击 "+" 添加所有文件
5. 填写提交信息
6. 点击 "✓" 提交
7. 点击 "..." → "Push"

## 🔍 上传前检查清单

### ✅ 必须检查

- [ ] `.env` 文件已被忽略（不会上传）
- [ ] `.env.example` 文件已包含（作为模板）
- [ ] 所有 `.pem` 文件已被忽略
- [ ] `master_key.bin` 已被忽略
- [ ] API密钥已从代码中移除

### ✅ 建议检查

- [ ] README文件已更新
- [ ] 文档完整
- [ ] 测试通过
- [ ] 代码格式化

## 🔒 安全检查

### 检查是否包含敏感信息

```bash
# 搜索可能的API密钥
git grep -i "api_key"
git grep -i "sk-"

# 搜索密码
git grep -i "password"

# 搜索证书
git grep -i "BEGIN PRIVATE KEY"
```

### 如果发现敏感信息

```bash
# 从暂存区移除
git reset HEAD <file>

# 添加到.gitignore
echo "<file>" >> .gitignore
```

## 📝 推荐的提交信息

### 首次提交
```
Initial commit: Multi-robot security platform

Features:
- Real-time task visualization with interactive map
- Security monitoring dashboard
- Attack simulation lab (8 attack types)
- Certificate management system
- AI-powered task parsing (OpenAI, Claude, Qwen)
- Complete audit logging
```

### 后续提交
```
feat: Add new feature
fix: Fix bug
docs: Update documentation
style: Format code
refactor: Refactor code
test: Add tests
chore: Update dependencies
```

## 🌐 创建GitHub仓库

### 1. 访问GitHub
https://github.com/new

### 2. 填写信息
- **Repository name**: `puppy-secops-platform`
- **Description**: Multi-robot security verification platform with AI integration
- **Visibility**: Public 或 Private
- **不要**勾选 "Initialize with README"（我们已经有了）

### 3. 创建仓库

### 4. 按照GitHub提示操作
```bash
git remote add origin https://github.com/your-username/puppy-secops-platform.git
git branch -M main
git push -u origin main
```

## 📄 推荐的仓库设置

### README.md
将 `README_GITHUB.md` 重命名为 `README.md`：
```bash
mv README_GITHUB.md README.md
git add README.md
git commit -m "docs: Add README"
git push
```

### Topics（标签）
在GitHub仓库页面添加标签：
- `python`
- `fastapi`
- `security`
- `robotics`
- `ai`
- `openai`
- `visualization`
- `websocket`

### License
建议添加MIT License：
1. 在GitHub仓库页面点击 "Add file" → "Create new file"
2. 文件名输入 `LICENSE`
3. 点击 "Choose a license template"
4. 选择 "MIT License"
5. 提交

## 🎯 上传后的工作

### 1. 验证
访问您的GitHub仓库，确认：
- [ ] 文件已正确上传
- [ ] 敏感文件未上传
- [ ] README显示正常
- [ ] 文档可访问

### 2. 设置
- [ ] 添加仓库描述
- [ ] 添加Topics标签
- [ ] 设置GitHub Pages（如果需要）
- [ ] 配置Actions（如果需要CI/CD）

### 3. 分享
- [ ] 更新项目链接
- [ ] 分享给团队
- [ ] 添加到个人主页

## ⚠️ 常见问题

### Q: .env文件会被上传吗？
A: 不会，已在.gitignore中配置。

### Q: 如何验证敏感文件未上传？
A: 在GitHub仓库页面搜索文件名，如果找不到就是未上传。

### Q: 如果不小心上传了敏感信息怎么办？
A: 
1. 立即删除文件并提交
2. 更改所有泄露的密钥
3. 使用 `git filter-branch` 清理历史（高级）

### Q: 可以上传到私有仓库吗？
A: 可以，创建仓库时选择Private。

## 📞 需要帮助？

如果遇到问题：
1. 查看Git错误信息
2. 检查.gitignore配置
3. 验证远程仓库地址
4. 查看GitHub文档

---

**准备好了吗？开始上传到GitHub！** 🚀
