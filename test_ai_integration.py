#!/usr/bin/env python3
"""
AI接口集成测试脚本
测试不同AI提供者的任务解析功能
"""

import asyncio
import os
import sys


async def test_ai_parsing():
    """测试AI解析功能"""
    
    print("=" * 60)
    print("AI接口集成测试")
    print("=" * 60)
    
    # 导入nl_agent模块
    try:
        from app.core.nl_agent import parse_natural_task_async, _ai_provider
    except ImportError as e:
        print(f"❌ 导入失败: {e}")
        print("请确保在项目根目录运行此脚本")
        return False
    
    # 检查AI提供者状态
    print("\n[1] 检查AI配置")
    if _ai_provider:
        provider_type = type(_ai_provider).__name__
        print(f"✅ AI提供者: {provider_type}")
    else:
        print("⚠️  未配置AI提供者，将使用规则引擎")
        print("提示: 设置环境变量 AI_PROVIDER 和 AI_API_KEY")
    
    # 测试用例
    test_cases = [
        {
            "input": "紧急！送医疗物资到B区",
            "expected": {
                "site": "zone_b",
                "priority": 5,
                "cargo_type": "medical"
            }
        },
        {
            "input": "需要尽快把急救药品送到A区域",
            "expected": {
                "site": "zone_a",
                "priority": 4,
                "cargo_type": "medical"
            }
        },
        {
            "input": "帮我把文件送到C区吧，不着急",
            "expected": {
                "site": "zone_c",
                "priority": 2,
                "cargo_type": "document"
            }
        },
        {
            "input": "立即派送维修工具到D区",
            "expected": {
                "site": "zone_d",
                "priority": 5,
                "cargo_type": "repair"
            }
        },
        {
            "input": "送一些补给到充电站",
            "expected": {
                "site": "dock",
                "priority": 3,
                "cargo_type": "supply"
            }
        }
    ]
    
    print(f"\n[2] 运行测试用例 ({len(test_cases)}个)")
    print("-" * 60)
    
    passed = 0
    failed = 0
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n测试 {i}/{len(test_cases)}: {test['input']}")
        
        try:
            result = await parse_natural_task_async(test['input'])
            
            # 检查结果
            checks = []
            
            # 检查站点
            site_match = result['site'] == test['expected']['site']
            checks.append(("站点", result['site'], test['expected']['site'], site_match))
            
            # 检查优先级（允许±1的误差）
            priority_match = abs(result['priority'] - test['expected']['priority']) <= 1
            checks.append(("优先级", result['priority'], test['expected']['priority'], priority_match))
            
            # 检查货物类型
            cargo_match = result['cargo_type'] == test['expected']['cargo_type']
            checks.append(("货物", result['cargo_type'], test['expected']['cargo_type'], cargo_match))
            
            # 显示结果
            all_passed = all(check[3] for check in checks)
            
            for name, actual, expected, match in checks:
                status = "✅" if match else "❌"
                print(f"  {status} {name}: {actual} (期望: {expected})")
            
            # 显示来源
            source = result.get('source', 'unknown')
            source_label = {
                'ai_agent': '🤖 AI',
                'rule_engine': '📏 规则引擎',
                'unknown': '❓ 未知'
            }.get(source, source)
            print(f"  📍 来源: {source_label}")
            
            if all_passed:
                print(f"  ✅ 测试通过")
                passed += 1
            else:
                print(f"  ❌ 测试失败")
                failed += 1
                
        except Exception as e:
            print(f"  ❌ 异常: {e}")
            failed += 1
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    print(f"总计: {len(test_cases)} 个测试")
    print(f"✅ 通过: {passed}")
    print(f"❌ 失败: {failed}")
    print(f"成功率: {passed/len(test_cases)*100:.1f}%")
    
    if _ai_provider:
        print(f"\n💡 使用了AI解析")
    else:
        print(f"\n💡 使用了规则引擎")
        print(f"提示: 配置AI_API_KEY以启用AI解析")
    
    print("=" * 60)
    
    return failed == 0


async def test_performance():
    """测试性能"""
    import time
    from app.core.nl_agent import parse_natural_task_async
    
    print("\n" + "=" * 60)
    print("性能测试")
    print("=" * 60)
    
    test_text = "紧急！送医疗物资到B区"
    iterations = 5
    
    print(f"\n测试: 解析 '{test_text}' {iterations}次")
    
    start_time = time.time()
    
    for i in range(iterations):
        await parse_natural_task_async(test_text)
    
    end_time = time.time()
    total_time = end_time - start_time
    avg_time = total_time / iterations
    
    print(f"\n总耗时: {total_time:.3f}秒")
    print(f"平均耗时: {avg_time:.3f}秒/次")
    print(f"吞吐量: {1/avg_time:.2f}次/秒")
    
    if avg_time < 0.1:
        print("⚡ 性能: 极快（规则引擎）")
    elif avg_time < 2:
        print("🚀 性能: 快速（AI）")
    elif avg_time < 5:
        print("🐢 性能: 一般（AI）")
    else:
        print("🐌 性能: 较慢（AI或网络问题）")


def print_config_help():
    """打印配置帮助"""
    print("\n" + "=" * 60)
    print("配置指南")
    print("=" * 60)
    
    print("\n要启用AI解析，请设置以下环境变量：")
    print("\n1. OpenAI:")
    print("   export AI_PROVIDER=openai")
    print("   export AI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    
    print("\n2. Claude:")
    print("   export AI_PROVIDER=claude")
    print("   export AI_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    
    print("\n3. DeepSeek:")
    print("   export AI_PROVIDER=deepseek")
    print("   export AI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    
    print("\n或者创建 .env 文件:")
    print("   cp .env.example .env")
    print("   # 编辑 .env 文件填入您的配置")
    
    print("\n详细文档: AI接口配置指南.md")
    print("=" * 60)


async def main():
    """主函数"""
    
    # 运行功能测试
    success = await test_ai_parsing()
    
    # 运行性能测试
    await test_performance()
    
    # 如果未配置AI，显示配置帮助
    from app.core.nl_agent import _ai_provider
    if not _ai_provider:
        print_config_help()
    
    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  测试被中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
