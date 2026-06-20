import os
import re
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple


@dataclass
class RawTextShieldResult:
    decision: str
    risk_score: float
    label: str
    reasons: List[str]
    backend: str
    risk_tags: List[str] | None = None
    translated_text: Optional[str] = None
    model_input: Optional[str] = None
    model_label: Optional[str] = None
    model_score: float = 0.0
    heuristic_score: float = 0.0

    def to_dict(self):
        return asdict(self)


class RawTextShield:
    """RawShield 只负责提示注入/越狱前置检测。

    业务语义风险（越权、禁区、危险动作、审计逃避、指定机器狗等）全部交给
    TaskGuard-S 处理，避免 RawShield 和 TaskGuard 的边界混乱。
    """

    RAW_REASON_TO_TAG = {
        "override_rule_phrase": "prompt_injection",
        "direct_jailbreak_phrase": "jailbreak",
        "model_label_malicious": "prompt_injection",
        "model_label_injection": "prompt_injection",
        "model_label_prompt_injection": "prompt_injection",
        "model_label_jailbreak": "jailbreak",
        "model_label_unsafe": "prompt_injection",
        "model_label_attack": "prompt_injection",
    }

    def __init__(self):
        self.enabled = os.getenv("RAW_SHIELD_ENABLED", "true").lower() == "true"
        self.backend = os.getenv("RAW_SHIELD_BACKEND", "heuristic").strip()
        self.model_name = os.getenv("RAW_SHIELD_MODEL", "").strip()

        # 收紧 RawShield：PromptGuard 判断为恶意时更快进入 block。
        # 即使 .env 里还写着 0.80，这里也会把实际阻断阈值收紧到 <=0.60。
        configured_block = float(os.getenv("RAW_SHIELD_BLOCK_THRESHOLD", "0.60"))
        configured_confirm = float(os.getenv("RAW_SHIELD_CONFIRM_THRESHOLD", "0.45"))
        self.block_threshold = min(configured_block, 0.60)
        self.confirm_threshold = min(configured_confirm, 0.45)

        self._clf = None
        self._model_available = False

        if self.enabled and self.backend == "prompt_guard2":
            self._load_model()

    def _load_model(self):
        try:
            from transformers import pipeline

            self._clf = pipeline(
                "text-classification",
                model=self.model_name,
                tokenizer=self.model_name,
                top_k=None,
                truncation=True,
                max_length=512,
            )
            self._model_available = True
            print(f"[RawTextShield] Prompt Guard 2 loaded: {self.model_name}")
        except Exception as e:
            self._model_available = False
            self._clf = None
            print(f"[RawTextShield] Prompt Guard 2 load failed, fallback to heuristic: {e}")

    def _risk_tags_from_reasons(self, reasons: List[str]) -> List[str]:
        tags: List[str] = []
        for reason in reasons:
            tag = self.RAW_REASON_TO_TAG.get(reason)
            if tag and tag not in tags:
                tags.append(tag)
        return tags

    def scan_heuristic(self, text: str) -> RawTextShieldResult:
        heuristic_score, reasons = self._heuristic_scan(text)
        risk_tags = self._risk_tags_from_reasons(reasons)

        if heuristic_score >= self.block_threshold:
            decision = "block"
            label = "malicious"
        elif heuristic_score >= self.confirm_threshold:
            decision = "need_confirmation"
            label = "suspicious"
        else:
            decision = "allow"
            label = "benign"
            reasons = []
            risk_tags = []

        return RawTextShieldResult(
            decision=decision,
            risk_score=round(heuristic_score, 4),
            label=label,
            reasons=reasons,
            risk_tags=risk_tags,
            backend="heuristic",
            heuristic_score=round(heuristic_score, 4),
        )

    def scan(self, text: str, translated_text: Optional[str] = None) -> RawTextShieldResult:
        if not self.enabled:
            return RawTextShieldResult(
                decision="allow",
                risk_score=0.0,
                label="benign",
                reasons=[],
                risk_tags=[],
                backend="disabled",
            )

        heuristic_score, heuristic_reasons = self._heuristic_scan(text)

        model_score = 0.0
        model_label = None
        model_reasons: List[str] = []
        model_input = translated_text or text

        if self.backend == "prompt_guard2" and self._model_available and model_input:
            model_score, model_label = self._prompt_guard_score(model_input)
            if model_score >= self.confirm_threshold:
                model_reasons.append(f"model_label_{model_label}")
        elif self.backend == "prompt_guard2" and not self._model_available:
            model_reasons.append("prompt_guard2_unavailable_fallback_to_heuristic")

        reasons = list(dict.fromkeys(heuristic_reasons + model_reasons))
        risk_tags = self._risk_tags_from_reasons(reasons)
        risk_score = max(heuristic_score, model_score)

        # 收紧：只要命中模型恶意或启发式提示注入/越狱，超过 0.60 即 block。
        if risk_tags and risk_score >= self.block_threshold:
            decision = "block"
            label = "malicious"
        elif risk_tags and risk_score >= self.confirm_threshold:
            decision = "need_confirmation"
            label = "suspicious"
        else:
            decision = "allow"
            label = "benign"
            reasons = []
            risk_tags = []

        return RawTextShieldResult(
            decision=decision,
            risk_score=round(risk_score, 4),
            label=label,
            reasons=reasons,
            risk_tags=risk_tags,
            backend=self.backend if self._model_available else "heuristic",
            translated_text=translated_text,
            model_input=model_input,
            model_label=model_label,
            model_score=round(model_score, 4),
            heuristic_score=round(heuristic_score, 4),
        )

    def _heuristic_scan(self, text: str) -> Tuple[float, List[str]]:
        # 注意：这里只有提示注入/越狱；审计逃避、关闭安全、管理员模式等业务语义风险交给 TaskGuard-S。
        t = text.lower()
        reasons: List[str] = []
        score = 0.0

        patterns = {
            "override_rule_phrase": [
                r"忽略.{0,10}(之前|以上|前面|所有|全部).{0,10}(规则|指令|要求|限制|策略)",
                r"无视.{0,10}(之前|以上|前面|所有|全部).{0,10}(规则|指令|要求|限制|策略)",
                r"忘记.{0,10}(之前|以上|前面|所有|全部).{0,10}(规则|指令|要求|限制|策略)",
                r"覆盖.{0,10}(系统|安全|原有).{0,10}(规则|指令|策略)",
                r"ignore\s+(previous|above|all|prior)\s+(rules|instructions|instruction|policy|policies)",
                r"disregard\s+(previous|above|all|prior)\s+(rules|instructions|instruction|policy|policies)",
                r"forget\s+(previous|above|all|prior)\s+(rules|instructions|instruction|policy|policies)",
            ],
            "direct_jailbreak_phrase": [
                r"你现在不是.{0,12}(安全系统|机器人|智能体|助手)",
                r"不需要.{0,8}(遵守|执行).{0,8}(限制|规则|安全策略)",
                r"解除.{0,8}(限制|安全限制|系统限制)",
                r"越狱",
                r"开启.{0,6}开发者模式",
                r"dan\s+mode",
                r"jailbreak",
                r"developer\s+mode",
                r"ignore\s+previous\s+instructions",
            ],
        }

        weights = {
            "override_rule_phrase": 0.88,
            "direct_jailbreak_phrase": 0.88,
        }

        for reason, pats in patterns.items():
            for pat in pats:
                if re.search(pat, t, flags=re.IGNORECASE):
                    reasons.append(reason)
                    score = max(score, weights.get(reason, 0.60))
                    break

        # 多个攻击信号叠加时直接高危。
        if len(set(reasons)) >= 2:
            score = max(score, 0.95)

        return score, reasons

    def _prompt_guard_score(self, text: str) -> Tuple[float, str]:
        if not self._clf:
            return 0.0, "unavailable"

        try:
            raw = self._clf(text)
        except Exception as e:
            print(f"[RawTextShield] model inference failed: {e}")
            return 0.0, "model_error"

        items = raw
        if isinstance(raw, list) and raw and isinstance(raw[0], list):
            items = raw[0]

        score_map = {}
        for item in items:
            label = str(item.get("label", "")).lower().strip()
            label = label.replace(" ", "_").replace("-", "_")
            score = float(item.get("score", 0.0))
            score_map[label] = score

        malicious_score = max(
            score_map.get("malicious", 0.0),
            score_map.get("injection", 0.0),
            score_map.get("injection_detected", 0.0),
            score_map.get("prompt_injection", 0.0),
            score_map.get("jailbreak", 0.0),
            score_map.get("unsafe", 0.0),
            score_map.get("attack", 0.0),
            score_map.get("label_1", 0.0),
            score_map.get("1", 0.0),
        )

        benign_score = max(
            score_map.get("benign", 0.0),
            score_map.get("safe", 0.0),
            score_map.get("legit", 0.0),
            score_map.get("normal", 0.0),
            score_map.get("clean", 0.0),
            score_map.get("label_0", 0.0),
            score_map.get("0", 0.0),
        )

        if malicious_score >= benign_score and malicious_score > 0:
            # 模型只输出 malicious，标签语义统一归入 prompt_injection。
            return malicious_score, "malicious"

        return malicious_score, "benign"
