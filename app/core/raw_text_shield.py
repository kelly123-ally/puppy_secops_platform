import os
import re
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple


@dataclass
class RawTextShieldResult:
    decision: str
    risk_score: float
    label: str
    reasons: List[str]
    backend: str
    translated_text: Optional[str] = None
    model_input: Optional[str] = None
    model_label: Optional[str] = None
    model_score: float = 0.0
    heuristic_score: float = 0.0

    def to_dict(self):
        return asdict(self)


class RawTextShield:
    def __init__(self):
        self.enabled = os.getenv("RAW_SHIELD_ENABLED", "true").lower() == "true"
        self.backend = os.getenv("RAW_SHIELD_BACKEND", "heuristic").strip()
        self.model_name = os.getenv("RAW_SHIELD_MODEL", "").strip()

        self.block_threshold = float(os.getenv("RAW_SHIELD_BLOCK_THRESHOLD", "0.80"))
        self.confirm_threshold = float(os.getenv("RAW_SHIELD_CONFIRM_THRESHOLD", "0.45"))

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

    def scan_heuristic(self, text: str) -> RawTextShieldResult:
        heuristic_score, reasons = self._heuristic_scan(text)

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

        return RawTextShieldResult(
            decision=decision,
            risk_score=round(heuristic_score, 4),
            label=label,
            reasons=reasons,
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

        risk_score = max(heuristic_score, model_score)
        reasons = list(dict.fromkeys(heuristic_reasons + model_reasons))

        if risk_score >= self.block_threshold:
            decision = "block"
            label = "malicious"
        elif risk_score >= self.confirm_threshold:
            decision = "need_confirmation"
            label = "suspicious"
        else:
            decision = "allow"
            label = "benign"
            reasons = []

        return RawTextShieldResult(
            decision=decision,
            risk_score=round(risk_score, 4),
            label=label,
            reasons=reasons,
            backend=self.backend if self._model_available else "heuristic",
            translated_text=translated_text,
            model_input=model_input,
            model_label=model_label,
            model_score=round(model_score, 4),
            heuristic_score=round(heuristic_score, 4),
        )

    def _heuristic_scan(self, text: str) -> Tuple[float, List[str]]:
        t = text.lower()
        reasons: List[str] = []
        score = 0.0

        patterns = {
            "override_rule_phrase": [
                r"忽略.{0,8}(之前|以上|前面).{0,8}(规则|指令|要求)",
                r"无视.{0,8}(规则|限制|安全策略|安全闸门)",
                r"忘记.{0,8}(规则|限制|安全策略)",
                r"覆盖.{0,8}(规则|策略|限制)",
                r"ignore\s+(previous|above|all)\s+(rules|instructions|policy|policies)",
                r"disregard\s+(previous|above|all)\s+(rules|instructions)",
            ],
            "disable_security_phrase": [
                r"绕过.{0,8}(安全|闸门|检查|策略|审核)",
                r"跳过.{0,8}(安全|闸门|检查|策略|审核)",
                r"关闭.{0,8}(安全|闸门|检查|审计|日志)",
                r"禁用.{0,8}(安全|闸门|检查|审计|日志)",
                r"bypass\s+(security|safety|guard|check|checks|policy)",
                r"disable\s+(security|safety|guard|audit|logging)",
            ],
            "audit_evasion_phrase": [
                r"不要.{0,8}(记录|日志|审计|上报)",
                r"别.{0,8}(记录|日志|审计|上报)",
                r"不写.{0,8}(日志|审计)",
                r"秘密执行",
                r"暗中执行",
                r"不要告诉",
                r"do\s+not\s+(log|record|audit|report)",
                r"don't\s+(log|record|audit|report)",
                r"secretly\s+execute",
            ],
            "privilege_escalation_phrase": [
                r"管理员模式",
                r"最高权限",
                r"超级用户",
                r"root权限",
                r"开发者模式",
                r"强制执行",
                r"admin\s+mode",
                r"administrator\s+mode",
                r"root\s+permission",
                r"developer\s+mode",
                r"force\s+execute",
            ],
            "direct_jailbreak_phrase": [
                r"你现在不是",
                r"解除限制",
                r"越狱",
                r"jailbreak",
                r"dan\s+mode",
                r"developer\s+mode",
                r"ignore\s+previous\s+instructions",
            ],
        }

        weights = {
            "override_rule_phrase": 0.70,
            "disable_security_phrase": 0.70,
            "audit_evasion_phrase": 0.55,
            "privilege_escalation_phrase": 0.65,
            "direct_jailbreak_phrase": 0.70,
        }

        for reason, pats in patterns.items():
            for pat in pats:
                if re.search(pat, t, flags=re.IGNORECASE):
                    reasons.append(reason)
                    score = max(score, weights.get(reason, 0.45))
                    break

        reason_set = set(reasons)

        if "override_rule_phrase" in reason_set and "disable_security_phrase" in reason_set:
            score = max(score, 0.82)

        if "disable_security_phrase" in reason_set and "audit_evasion_phrase" in reason_set:
            score = max(score, 0.90)

        if len(reason_set) >= 3:
            score = max(score, 0.90)

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
            return malicious_score, "malicious"

        return malicious_score, "benign"
