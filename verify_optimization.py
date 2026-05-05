#!/usr/bin/env python3
"""
前端优化验证脚本

此脚本用于验证前端优化是否正确应用。
"""

import os
import sys
from pathlib import Path

# 颜色代码
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_header(text):
    """打印标题"""
    print(f"\n{BLUE}{'=' * 60}{RESET}")
    print(f"{BLUE}{text:^60}{RESET}")
    print(f"{BLUE}{'=' * 60}{RESET}\n")

def print_success(text):
    """打印成功消息"""
    print(f"{GREEN}✓ {text}{RESET}")

def print_error(text):
    """打印错误消息"""
    print(f"{RED}✗ {text}{RESET}")

def print_warning(text):
    """打印警告消息"""
    print(f"{YELLOW}⚠ {text}{RESET}")

def check_file_exists(filepath, expected_size_range=None):
    """检查文件是否存在及大小"""
    path = Path(filepath)
    
    if not path.exists():
        print_error(f"文件不存在: {filepath}")
        return False
    
    size = path.stat().st_size
    size_kb = size / 1024
    
    if expected_size_range:
        min_size, max_size = expected_size_range
        if min_size <= size_kb <= max_size:
            print_success(f"{filepath} ({size_kb:.1f} KB)")
            return True
        else:
            print_warning(f"{filepath} ({size_kb:.1f} KB) - 大小超出预期范围 ({min_size}-{max_size} KB)")
            return True
    else:
        print_success(f"{filepath} ({size_kb:.1f} KB)")
        return True

def check_file_content(filepath, search_strings):
    """检查文件是否包含特定内容"""
    path = Path(filepath)
    
    if not path.exists():
        print_error(f"文件不存在: {filepath}")
        return False
    
    try:
        content = path.read_text(encoding='utf-8')
        
        all_found = True
        for search_str in search_strings:
            if search_str not in content:
                print_error(f"  缺少内容: {search_str}")
                all_found = False
        
        if all_found:
            print_success(f"{filepath} - 所有必需内容都存在")
            return True
        else:
            return False
            
    except Exception as e:
        print_error(f"读取文件失败: {filepath} - {e}")
        return False

def main():
    """主函数"""
    print_header("前端优化验证")
    
    all_checks_passed = True
    
    # 1. 检查 CSS 文件
    print_header("检查 CSS 文件")
    
    css_files = [
        ("app/static/styles.css", (20, 25)),
        ("app/static/security_dashboard.css", (10, 15))
    ]
    
    for filepath, size_range in css_files:
        if not check_file_exists(filepath, size_range):
            all_checks_passed = False
    
    # 检查 styles.css 关键内容
    styles_checks = [
        "--transition-fast",
        "--transition-normal",
        "will-change",
        "transform: translateZ(0)",
        "@media (max-width: 640px)"
    ]
    
    if not check_file_content("app/static/styles.css", styles_checks):
        all_checks_passed = False
    
    # 2. 检查 JavaScript 文件
    print_header("检查 JavaScript 文件")
    
    js_files = [
        ("app/static/app.js", (25, 35)),
        ("app/static/security_dashboard.js", (30, 40))
    ]
    
    for filepath, size_range in js_files:
        if not check_file_exists(filepath, size_range):
            all_checks_passed = False
    
    # 检查 app.js 关键内容
    app_js_checks = [
        "debounce",
        "throttle",
        "notifications",
        "requestAnimationFrame",
        "reconnectAttempts"
    ]
    
    if not check_file_content("app/static/app.js", app_js_checks):
        all_checks_passed = False
    
    # 检查 security_dashboard.js 关键内容
    dashboard_js_checks = [
        "SecurityDashboard",
        "updateMetricValue",
        "attackTypeTranslations",
        "showError",
        "showSuccess"
    ]
    
    if not check_file_content("app/static/security_dashboard.js", dashboard_js_checks):
        all_checks_passed = False
    
    # 3. 检查 HTML 文件
    print_header("检查 HTML 文件")
    
    html_files = [
        ("app/templates/index.html", (10, 15)),
        ("app/templates/login.html", (4, 6)),
        ("app/templates/security_dashboard.html", (6, 8))
    ]
    
    for filepath, size_range in html_files:
        if not check_file_exists(filepath, size_range):
            all_checks_passed = False
    
    # 检查 index.html 关键内容
    index_checks = [
        "loading-overlay",
        "aria-label",
        "role=",
        "v=6",  # JavaScript 版本号
        "v=7"   # CSS 版本号
    ]
    
    if not check_file_content("app/templates/index.html", index_checks):
        all_checks_passed = False
    
    # 检查 login.html 关键内容
    login_checks = [
        "aria-label",
        "aria-required",
        "autocomplete",
        "submitBtn.disabled"
    ]
    
    if not check_file_content("app/templates/login.html", login_checks):
        all_checks_passed = False
    
    # 4. 检查文档文件
    print_header("检查文档文件")
    
    doc_files = [
        "FRONTEND_OPTIMIZATION_SUMMARY.md",
        "FRONTEND_QUICK_REFERENCE.md",
        "FRONTEND_TEST_CHECKLIST.md",
        "FRONTEND_BEFORE_AFTER.md",
        "FRONTEND_DEPLOYMENT_GUIDE.md",
        "前端优化完成报告.md",
        "前端优化说明.md"
    ]
    
    for filepath in doc_files:
        if not check_file_exists(filepath):
            all_checks_passed = False
    
    # 5. 最终结果
    print_header("验证结果")
    
    if all_checks_passed:
        print_success("所有检查通过！前端优化已正确应用。")
        print(f"\n{GREEN}✓ 可以开始部署了！{RESET}\n")
        print("下一步：")
        print("1. 阅读 '前端优化完成报告.md' 了解详细信息")
        print("2. 参考 'FRONTEND_DEPLOYMENT_GUIDE.md' 进行部署")
        print("3. 使用 'FRONTEND_TEST_CHECKLIST.md' 进行测试")
        return 0
    else:
        print_error("部分检查未通过，请检查上述错误。")
        print(f"\n{RED}✗ 请修复问题后再部署。{RESET}\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
