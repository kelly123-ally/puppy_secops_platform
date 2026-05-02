from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class LBSEError(Exception):
    pass


class LBSENonceReplayError(LBSEError):
    pass


class LBSEIntegrityError(LBSEError):
    pass


class LBSELeaseError(LBSEError):
    pass


class LBSERevokedError(LBSEError):
    pass


@dataclass
class LBSEHeader:
    version: int
    msg_type: str
    sender_id: str
    receiver_id: str
    session_id: str
    seq: int
    timestamp_ms: int
    task_id: Optional[str]
    lease_id: Optional[str]
    role: str
    key_id: str


class LeaseBoundSecureEnvelope:
    """
    LBSE = Lease-Bound Secure Envelope

    - 底层：AES-GCM
    - 关联数据（AAD）：header
    - 业务绑定：task_id / lease_id / sender / receiver / seq / timestamp
    """

    def __init__(self, master_key: bytes | None = None, clock_skew_ms: int = 30_000) -> None:
        self.master_key = master_key or secrets.token_bytes(32)
        self.clock_skew_ms = clock_skew_ms
        self.send_seq: Dict[Tuple[str, str, str], int] = {}
        self.recv_seq: Dict[Tuple[str, str], int] = {}
        self.nonce_cache: Dict[Tuple[str, str], int] = {}

    @staticmethod
    def _b64e(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def _b64d(text: str) -> bytes:
        return base64.b64decode(text.encode("utf-8"))

    @staticmethod
    def _canonical(obj: Dict[str, Any]) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _derive_key(self, session_id: str, key_id: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_id.encode("utf-8"),
            info=f"LBSE::{session_id}".encode("utf-8"),
        )
        return hkdf.derive(self.master_key)

    def next_seq(self, sender_id: str, receiver_id: str, session_id: str) -> int:
        k = (sender_id, receiver_id, session_id)
        n = self.send_seq.get(k, 0) + 1
        self.send_seq[k] = n
        return n

    def seal(
        self,
        *,
        msg_type: str,
        sender_id: str,
        receiver_id: str,
        session_id: str,
        role: str,
        payload: Dict[str, Any],
        task_id: Optional[str] = None,
        lease_id: Optional[str] = None,
        key_id: str = "lbse-k1",
        seq: Optional[int] = None,
    ) -> Dict[str, Any]:
        seq = seq or self.next_seq(sender_id, receiver_id, session_id)
        header = LBSEHeader(
            version=1,
            msg_type=msg_type,
            sender_id=sender_id,
            receiver_id=receiver_id,
            session_id=session_id,
            seq=seq,
            timestamp_ms=int(time.time() * 1000),
            task_id=task_id,
            lease_id=lease_id,
            role=role,
            key_id=key_id,
        )
        header_dict = asdict(header)
        aad = self._canonical(header_dict)
        key = self._derive_key(session_id=session_id, key_id=key_id)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, self._canonical(payload), aad)

        return {
            "header": header_dict,
            "nonce": self._b64e(nonce),
            "ciphertext": self._b64e(ciphertext),
        }

    def open_and_verify(
        self,
        packet: Dict[str, Any],
        *,
        expected_receiver: Optional[str] = None,
        revoked_set: Optional[set[str]] = None,
        active_lease_lookup: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
        enforce_seq: bool = True,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        if "header" not in packet or "nonce" not in packet or "ciphertext" not in packet:
            raise LBSEIntegrityError("malformed_lbse_packet")

        header = dict(packet["header"])
        sender_id = header["sender_id"]
        receiver_id = header["receiver_id"]
        session_id = header["session_id"]
        key_id = header["key_id"]
        seq = int(header["seq"])
        timestamp_ms = int(header["timestamp_ms"])
        nonce_key = (sender_id, packet["nonce"])

        if expected_receiver and receiver_id != expected_receiver:
            raise LBSEIntegrityError("receiver_mismatch")

        if revoked_set and sender_id in revoked_set:
            raise LBSERevokedError("sender_revoked")

        now_ms = int(time.time() * 1000)
        if abs(now_ms - timestamp_ms) > self.clock_skew_ms:
            raise LBSENonceReplayError("stale_timestamp")

        if nonce_key in self.nonce_cache:
            raise LBSENonceReplayError("replayed_nonce")
        self.nonce_cache[nonce_key] = now_ms
        self._gc_nonce_cache(now_ms)

        if enforce_seq:
            recv_key = (sender_id, session_id)
            prev = self.recv_seq.get(recv_key, 0)
            if seq <= prev:
                raise LBSENonceReplayError("replayed_or_out_of_order_seq")
            self.recv_seq[recv_key] = seq

        aad = self._canonical(header)
        key = self._derive_key(session_id=session_id, key_id=key_id)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(self._b64d(packet["nonce"]), self._b64d(packet["ciphertext"]), aad)
        except Exception as exc:
            raise LBSEIntegrityError("aead_verify_failed") from exc

        payload = json.loads(plaintext.decode("utf-8"))

        task_id = header.get("task_id")
        lease_id = header.get("lease_id")
        if task_id and active_lease_lookup and header["msg_type"] in {"Heartbeat", "CompleteTask", "AckAssignment"}:
            active = active_lease_lookup(task_id)
            if active is None:
                raise LBSELeaseError("no_active_assignment")
            if lease_id != active.get("lease_id"):
                raise LBSELeaseError("lease_mismatch")
            if active.get("robot_id") and sender_id != active.get("robot_id"):
                raise LBSELeaseError("sender_not_current_holder")

        return header, payload

    def _gc_nonce_cache(self, now_ms: int) -> None:
        stale = [k for k, ts in self.nonce_cache.items() if now_ms - ts > 300_000]
        for k in stale:
            self.nonce_cache.pop(k, None)
