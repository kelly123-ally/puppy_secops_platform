from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Optional, Tuple


class SecurityEngine:
    def __init__(self, secret: Optional[str] = None):
        self.secret = (secret or secrets.token_hex(16)).encode("utf-8")
        self.used_nonces: Dict[str, float] = {}

    def canonical_payload(self, payload: dict) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, payload: dict) -> Tuple[str, str, float]:
        nonce = secrets.token_hex(8)
        timestamp = time.time()
        signed_payload = dict(payload)
        signed_payload["nonce"] = nonce
        signed_payload["timestamp"] = timestamp
        digest = hmac.new(self.secret, self.canonical_payload(signed_payload), hashlib.sha256).hexdigest()
        return digest, nonce, timestamp

    def verify(
        self,
        payload: dict,
        signature: Optional[str],
        require_signature: bool = True,
        replay_protection: bool = True,
        max_skew_sec: float = 60.0,
    ) -> Tuple[bool, str]:
        nonce = payload.get("nonce")
        timestamp = float(payload.get("timestamp", 0.0))

        if require_signature and not signature:
            return False, "missing_signature"

        if require_signature:
            expected = hmac.new(self.secret, self.canonical_payload(payload), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature or ""):
                return False, "signature_mismatch"

        now = time.time()
        if abs(now - timestamp) > max_skew_sec:
            return False, "stale_timestamp"

        if replay_protection:
            if not nonce:
                return False, "missing_nonce"
            if nonce in self.used_nonces:
                return False, "replayed_nonce"
            self.used_nonces[nonce] = now

        self._gc_nonces(now)
        return True, "ok"

    def _gc_nonces(self, now: float) -> None:
        stale = [nonce for nonce, ts in self.used_nonces.items() if now - ts > 300]
        for nonce in stale:
            self.used_nonces.pop(nonce, None)
