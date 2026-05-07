from __future__ import annotations

import itertools
import re
import os
import json
from typing import Dict, Tuple, Optional
import httpx


SITE_MAP: Dict[str, Tuple[int, int]] = {
    "zone_a": (5, 4),
    "zone_b": (24, 4),
    "zone_c": (8, 14),
    "zone_d": (24, 14),
    "dock": (2, 2),
}

_counter = itertools.count(1)


class AIProvider:
    """AI接口提供者基类"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def parse_task(self, text: str) -> dict:
        """使用AI解析任务"""
        raise NotImplementedError


class OpenAIProvider(AIProvider):
    """OpenAI接口（支持GPT-3.5/GPT-4）"""
    
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo", base_url: str = "https://api.openai.com/v1"):
        super().__init__(api_key)
        self.model = model
        self.base_url = base_url
    
    async def parse_task(self, text: str) -> dict:
        """使用OpenAI解析任务"""
        system_prompt = """你是一个物流任务解析助手。用户会用自然语言描述任务，你需要提取以下信息：

站点（site）：
- zone_a / a区 / A区域
- zone_b / b区 / B区域  
- zone_c / c区 / C区域
- zone_d / d区 / D区域
- dock / 充电站 / 回充

优先级（priority）：1-5，其中：
- 5: 最高优先级（紧急、立即、急需）
- 4: 高优先级（尽快、优先）
- 3: 中等优先级（一般、普通）
- 2: 低优先级（不急）
- 1: 最低优先级

货物类型（cargo_type）：
- medical: 医疗、药品、急救
- food: 食物、餐饮
- supply: 补给、物资
- repair: 维修、工具
- document: 文档、文件
- battery: 电池、能源
- equipment: 设备、器材

请以JSON格式返回，格式如下：
{
  "site": "zone_a",
  "priority": 5,
  "cargo_type": "medical"
}

只返回JSON，不要其他解释。"""

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": text}
                        ],
                        "temperature": 0.3,
                        "max_tokens": 200
                    }
                )
                
                if response.status_code == 200:
                    result = response.json()
                    content = result["choices"][0]["message"]["content"].strip()
                    
                    # 提取JSON（可能被markdown包裹）
                    if "```json" in content:
                        content = content.split("```json")[1].split("```")[0].strip()
                    elif "```" in content:
                        content = content.split("```")[1].split("```")[0].strip()
                    
                    parsed = json.loads(content)
                    return parsed
                else:
                    print(f"OpenAI API error: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"OpenAI API exception: {e}")
            return None


class ClaudeProvider(AIProvider):
    """Anthropic Claude接口"""
    
    def __init__(self, api_key: str, model: str = "claude-3-haiku-20240307"):
        super().__init__(api_key)
        self.model = model
    
    async def parse_task(self, text: str) -> dict:
        """使用Claude解析任务"""
        system_prompt = """你是一个物流任务解析助手。用户会用自然语言描述任务，你需要提取以下信息：

站点（site）：zone_a, zone_b, zone_c, zone_d, dock
优先级（priority）：1-5（5最高）
货物类型（cargo_type）：medical, food, supply, repair, document, battery, equipment

请以JSON格式返回：{"site": "zone_a", "priority": 5, "cargo_type": "medical"}
只返回JSON，不要其他解释。"""

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "max_tokens": 200,
                        "system": system_prompt,
                        "messages": [
                            {"role": "user", "content": text}
                        ]
                    }
                )
                
                if response.status_code == 200:
                    result = response.json()
                    content = result["content"][0]["text"].strip()
                    
                    # 提取JSON
                    if "```json" in content:
                        content = content.split("```json")[1].split("```")[0].strip()
                    elif "```" in content:
                        content = content.split("```")[1].split("```")[0].strip()
                    
                    parsed = json.loads(content)
                    return parsed
                else:
                    print(f"Claude API error: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"Claude API exception: {e}")
            return None


class DeepSeekProvider(AIProvider):
    """DeepSeek接口（兼容OpenAI格式）"""
    
    def __init__(self, api_key: str, model: str = "deepseek-chat"):
        super().__init__(api_key)
        self.model = model
        self.base_url = "https://api.deepseek.com/v1"
    
    async def parse_task(self, text: str) -> dict:
        """使用DeepSeek解析任务"""
        # 使用OpenAI兼容接口
        openai_provider = OpenAIProvider(self.api_key, self.model, self.base_url)
        return await openai_provider.parse_task(text)


# 全局AI提供者实例
_ai_provider: Optional[AIProvider] = None


def init_ai_provider():
    """初始化AI提供者"""
    global _ai_provider
    
    # 优先级：环境变量配置
    provider_type = os.getenv("AI_PROVIDER", "").lower()  # openai, claude, deepseek
    api_key = os.getenv("AI_API_KEY", "")
    
    if not api_key:
        print("未配置AI_API_KEY，将使用规则引擎")
        return
    
    try:
        if provider_type == "openai":
            model = os.getenv("AI_MODEL", "gpt-3.5-turbo")
            base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1")
            _ai_provider = OpenAIProvider(api_key, model, base_url)
            print(f"AI接口已启用: OpenAI ({model})")
            
        elif provider_type == "claude":
            model = os.getenv("AI_MODEL", "claude-3-haiku-20240307")
            _ai_provider = ClaudeProvider(api_key, model)
            print(f"AI接口已启用: Claude ({model})")
            
        elif provider_type == "deepseek":
            model = os.getenv("AI_MODEL", "deepseek-chat")
            _ai_provider = DeepSeekProvider(api_key, model)
            print(f"AI接口已启用: DeepSeek ({model})")
            
        else:
            print(f"未知的AI提供者: {provider_type}，将使用规则引擎")
            
    except Exception as e:
        print(f"AI接口初始化失败: {e}，将使用规则引擎")


# 规则引擎（备用方案）
def infer_site(text: str) -> str:
    lowered = text.lower()
    mapping = {
        "a区": "zone_a",
        "a区域": "zone_a",
        "zone_a": "zone_a",
        "b区": "zone_b",
        "b区域": "zone_b",
        "zone_b": "zone_b",
        "c区": "zone_c",
        "c区域": "zone_c",
        "zone_c": "zone_c",
        "d区": "zone_d",
        "d区域": "zone_d",
        "zone_d": "zone_d",
        "充电": "dock",
        "回充": "dock",
        "dock": "dock",
    }
    for key, value in mapping.items():
        if key in lowered or key in text:
            return value
    return "zone_a"


def infer_priority(text: str) -> int:
    if any(k in text for k in ["最高", "紧急", "立即", "急需", "高优先"]):
        return 5
    if any(k in text for k in ["高", "尽快", "优先"]):
        return 4
    if any(k in text for k in ["中", "一般"]):
        return 3
    if any(k in text for k in ["低", "不急"]):
        return 2
    return 3


def infer_cargo(text: str) -> str:
    checks = [
        ("药", "medical"),
        ("医疗", "medical"),
        ("急救", "medical"),
        ("食物", "food"),
        ("补给", "supply"),
        ("维修", "repair"),
        ("工具", "repair"),
        ("文档", "document"),
        ("电池", "battery"),
    ]
    for token, cargo in checks:
        if token in text:
            return cargo
    return "supply"


async def parse_natural_task_async(text: str, requested_by: str = "operator") -> dict:
    """异步解析自然语言任务（优先使用AI）"""
    
    # 尝试使用AI解析
    if _ai_provider:
        try:
            ai_result = await _ai_provider.parse_task(text)
            if ai_result and "site" in ai_result:
                site = ai_result.get("site", "zone_a")
                priority = ai_result.get("priority", 3)
                cargo_type = ai_result.get("cargo_type", "supply")
                
                # 验证站点
                if site not in SITE_MAP:
                    site = "zone_a"
                
                # 验证优先级
                if not isinstance(priority, int) or priority < 1 or priority > 5:
                    priority = 3
                
                x, y = SITE_MAP[site]
                
                return {
                    "task_id": f"nl_{next(_counter):03d}",
                    "site": site,
                    "x": x,
                    "y": y,
                    "priority": priority,
                    "cargo_type": cargo_type,
                    "note": text.strip(),
                    "requested_by": requested_by,
                    "source": "ai_agent",
                }
        except Exception as e:
            print(f"AI解析失败，回退到规则引擎: {e}")
    
    # 回退到规则引擎
    return parse_natural_task(text, requested_by)


def parse_natural_task(text: str, requested_by: str = "operator") -> dict:
    """同步解析自然语言任务（规则引擎）"""
    site = infer_site(text)
    x, y = SITE_MAP[site]
    return {
        "task_id": f"nl_{next(_counter):03d}",
        "site": site,
        "x": x,
        "y": y,
        "priority": infer_priority(text),
        "cargo_type": infer_cargo(text),
        "note": text.strip(),
        "requested_by": requested_by,
        "source": "rule_engine",
    }


# 启动时初始化AI提供者
init_ai_provider()
