"""
Audit Logger for PuppySecOps Platform

Provides tamper-proof audit logging using:
- Cryptographic hash chains (each event links to previous)
- Digital signatures (ECDSA or RSA-SHA256)
- Genesis hash for chain verification
- Compliance report export (JSON, CSV)

Requirements: 9.1-9.6, 10.1-10.5, 11.1-11.6, 24.1-24.6
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass
class AuditEvent:
    """Immutable audit log entry with cryptographic linking.
    
    Attributes:
        event_id: Unique event identifier
        timestamp: Unix timestamp when event occurred
        category: Event category (authentication, authorization, key_rotation, etc.)
        title: Brief event description
        actor: Who performed the action (user, robot_id, or system)
        details: Additional event-specific information
        previous_hash: SHA-256 hash of previous event (forms chain)
        event_hash: SHA-256 hash of this event
        signature: Digital signature of event_hash
    """
    event_id: str
    timestamp: float
    category: str
    title: str
    actor: str
    details: Dict[str, Any]
    previous_hash: str
    event_hash: str
    signature: str


class AuditLogger:
    """Tamper-proof audit logger with cryptographic hash chains.
    
    Each audit event is cryptographically linked to the previous event,
    forming a chain where any tampering breaks the chain integrity.
    All events are digitally signed for external verification.
    """
    
    def __init__(
        self,
        signing_key_path: Optional[str] = None,
        genesis_hash_path: Optional[str] = None,
        storage_path: Optional[str] = None
    ):
        """Initialize Audit Logger.
        
        Args:
            signing_key_path: Path to private signing key (PEM format)
            genesis_hash_path: Path to store genesis hash
            storage_path: Path to store audit events
            
        Raises:
            FileNotFoundError: If signing key not found
        """
        self.signing_key_path = signing_key_path or "audit_signing_key.pem"
        self.genesis_hash_path = genesis_hash_path or "genesis_hash.txt"
        self.storage_path = storage_path or "audit_events.json"
        
        # Load or generate signing key
        self.signing_key = self._load_or_generate_signing_key()
        
        # Storage for audit events
        self.events: List[AuditEvent] = []
        
        # Genesis hash (first event hash)
        self.genesis_hash: Optional[str] = self._load_genesis_hash()
        
        # Load existing events
        self._load_events()
    
    def _load_or_generate_signing_key(self) -> rsa.RSAPrivateKey:
        """Load signing key from file or generate new one.
        
        Returns:
            RSA private key for signing
        """
        key_path = Path(self.signing_key_path)
        
        if key_path.exists():
            with open(key_path, 'rb') as f:
                key_data = f.read()
            return serialization.load_pem_private_key(key_data, password=None)
        else:
            # Generate new signing key
            signing_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Save key
            key_path.parent.mkdir(parents=True, exist_ok=True)
            with open(key_path, 'wb') as f:
                f.write(signing_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            return signing_key
    
    def _load_genesis_hash(self) -> Optional[str]:
        """Load genesis hash from secure storage.
        
        Returns:
            Genesis hash or None if not yet created
        """
        genesis_path = Path(self.genesis_hash_path)
        if genesis_path.exists():
            with open(genesis_path, 'r') as f:
                return f.read().strip()
        return None
    
    def _save_genesis_hash(self, genesis_hash: str) -> None:
        """Save genesis hash to secure storage.
        
        Args:
            genesis_hash: Hash of first event
        """
        genesis_path = Path(self.genesis_hash_path)
        genesis_path.parent.mkdir(parents=True, exist_ok=True)
        with open(genesis_path, 'w') as f:
            f.write(genesis_hash)
    
    def _load_events(self) -> None:
        """Load existing audit events from storage."""
        storage_path = Path(self.storage_path)
        if not storage_path.exists():
            return
        
        try:
            with open(storage_path, 'r') as f:
                events_data = json.load(f)
            
            for event_data in events_data:
                event = AuditEvent(**event_data)
                self.events.append(event)
        except Exception:
            # If loading fails, start with empty event list
            pass
    
    def _save_events(self) -> None:
        """Persist audit events to storage."""
        storage_path = Path(self.storage_path)
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        events_data = [asdict(event) for event in self.events]
        
        with open(storage_path, 'w') as f:
            json.dump(events_data, f, indent=2)
    
    def _compute_event_hash(
        self,
        event_id: str,
        timestamp: float,
        category: str,
        title: str,
        actor: str,
        details: Dict[str, Any],
        previous_hash: str
    ) -> str:
        """Compute SHA-256 hash of event data.
        
        Args:
            event_id: Event identifier
            timestamp: Event timestamp
            category: Event category
            title: Event title
            actor: Event actor
            details: Event details
            previous_hash: Hash of previous event
            
        Returns:
            SHA-256 hash (hex string)
        """
        # Create canonical representation
        event_data = {
            "event_id": event_id,
            "timestamp": timestamp,
            "category": category,
            "title": title,
            "actor": actor,
            "details": details,
            "previous_hash": previous_hash
        }
        
        # Serialize to JSON with sorted keys for consistency
        event_json = json.dumps(event_data, sort_keys=True)
        
        # Compute SHA-256 hash
        hash_obj = hashlib.sha256(event_json.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def _sign_hash(self, event_hash: str) -> str:
        """Sign event hash with private key.
        
        Args:
            event_hash: Hash to sign
            
        Returns:
            Digital signature (hex string)
        """
        signature = self.signing_key.sign(
            event_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()
    
    def log_event(
        self,
        category: str,
        title: str,
        actor: str,
        details: Dict[str, Any]
    ) -> str:
        """Create audit event, compute hash, sign, and link to chain.
        
        Implements Requirements 9.1, 9.2, 9.4, 9.5, 10.1, 10.2, 10.5:
        - Computes SHA-256 hash of event
        - Links to previous event via previous_hash
        - Signs event with ECDSA or RSA-SHA256
        - Stores genesis hash in secure storage
        
        Args:
            category: Event category
            title: Brief event description
            actor: Who performed the action
            details: Additional event information
            
        Returns:
            Event ID
        """
        # Generate event ID
        event_id = secrets.token_hex(16)
        timestamp = time.time()
        
        # Get previous hash (or empty string for first event)
        if self.events:
            previous_hash = self.events[-1].event_hash
        else:
            previous_hash = ""
        
        # Compute event hash
        event_hash = self._compute_event_hash(
            event_id=event_id,
            timestamp=timestamp,
            category=category,
            title=title,
            actor=actor,
            details=details,
            previous_hash=previous_hash
        )
        
        # Sign event hash
        signature = self._sign_hash(event_hash)
        
        # Create audit event
        event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            category=category,
            title=title,
            actor=actor,
            details=details,
            previous_hash=previous_hash,
            event_hash=event_hash,
            signature=signature
        )
        
        # Store event
        self.events.append(event)
        
        # Save genesis hash if this is the first event
        if len(self.events) == 1:
            self.genesis_hash = event_hash
            self._save_genesis_hash(event_hash)
        
        # Persist events
        self._save_events()
        
        return event_id
    
    def verify_chain_integrity(self) -> Tuple[bool, Optional[int]]:
        """Verify entire audit chain from genesis to current.
        
        Implements Requirements 9.3, 9.6, 24.1, 24.2, 24.3, 24.4:
        - Verifies genesis hash matches stored value
        - Verifies each link in the chain
        - Verifies digital signatures on all events
        - Returns first tampered index if tampering detected
        
        Returns:
            Tuple of (valid, first_tampered_index)
            - valid: True if chain is intact, False if tampered
            - first_tampered_index: Index of first tampered event (None if valid)
        """
        if not self.events:
            return True, None
        
        # Verify genesis hash
        if self.genesis_hash and self.events[0].event_hash != self.genesis_hash:
            return False, 0
        
        # Verify each event in the chain
        for i, event in enumerate(self.events):
            # Verify hash computation
            computed_hash = self._compute_event_hash(
                event_id=event.event_id,
                timestamp=event.timestamp,
                category=event.category,
                title=event.title,
                actor=event.actor,
                details=event.details,
                previous_hash=event.previous_hash
            )
            
            if computed_hash != event.event_hash:
                return False, i
            
            # Verify signature
            try:
                public_key = self.signing_key.public_key()
                signature_bytes = bytes.fromhex(event.signature)
                public_key.verify(
                    signature_bytes,
                    event.event_hash.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception:
                return False, i
            
            # Verify chain link (except for first event)
            if i > 0:
                if event.previous_hash != self.events[i - 1].event_hash:
                    return False, i
        
        return True, None
    
    def export_compliance_report(
        self,
        start_time: float,
        end_time: float,
        format: str = "json"
    ) -> bytes:
        """Export audit events in specified format with signatures.
        
        Implements Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 10.3, 10.4:
        - Exports in JSON or CSV format
        - Includes all events within time range
        - Includes cryptographic signatures
        - Verifies chain integrity before export
        
        Args:
            start_time: Start of time range (Unix timestamp)
            end_time: End of time range (Unix timestamp)
            format: Export format ("json" or "csv")
            
        Returns:
            Exported report as bytes
            
        Raises:
            ValueError: If format is invalid or chain integrity fails
        """
        # Verify chain integrity before export
        valid, tampered_index = self.verify_chain_integrity()
        if not valid:
            raise ValueError(
                f"Audit chain integrity verification failed at index {tampered_index}. "
                "Cannot export tampered audit log."
            )
        
        # Filter events by time range
        filtered_events = [
            event for event in self.events
            if start_time <= event.timestamp <= end_time
        ]
        
        if format == "json":
            return self._export_json(filtered_events)
        elif format == "csv":
            return self._export_csv(filtered_events)
        else:
            raise ValueError(f"Unsupported format: {format}. Use 'json' or 'csv'.")
    
    def _export_json(self, events: List[AuditEvent]) -> bytes:
        """Export events as JSON.
        
        Args:
            events: Events to export
            
        Returns:
            JSON bytes
        """
        report = {
            "export_timestamp": time.time(),
            "total_events": len(events),
            "genesis_hash": self.genesis_hash,
            "public_key": self.get_public_key().decode('utf-8'),
            "events": [asdict(event) for event in events]
        }
        
        return json.dumps(report, indent=2).encode('utf-8')
    
    def _export_csv(self, events: List[AuditEvent]) -> bytes:
        """Export events as CSV.
        
        Args:
            events: Events to export
            
        Returns:
            CSV bytes
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'event_id', 'timestamp', 'category', 'title', 'actor',
            'details', 'previous_hash', 'event_hash', 'signature'
        ])
        
        # Write events
        for event in events:
            writer.writerow([
                event.event_id,
                event.timestamp,
                event.category,
                event.title,
                event.actor,
                json.dumps(event.details),
                event.previous_hash,
                event.event_hash,
                event.signature
            ])
        
        return output.getvalue().encode('utf-8')
    
    def get_public_key(self) -> bytes:
        """Return public key for external signature verification.
        
        Returns:
            Public key in PEM format
        """
        public_key = self.signing_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_events_by_category(self, category: str) -> List[AuditEvent]:
        """Get all events in a specific category.
        
        Args:
            category: Event category to filter by
            
        Returns:
            List of matching events
        """
        return [event for event in self.events if event.category == category]
    
    def get_events_by_actor(self, actor: str) -> List[AuditEvent]:
        """Get all events by a specific actor.
        
        Args:
            actor: Actor to filter by
            
        Returns:
            List of matching events
        """
        return [event for event in self.events if event.actor == actor]
    
    def get_events_in_time_range(
        self,
        start_time: float,
        end_time: float
    ) -> List[AuditEvent]:
        """Get all events within a time range.
        
        Args:
            start_time: Start of time range (Unix timestamp)
            end_time: End of time range (Unix timestamp)
            
        Returns:
            List of matching events
        """
        return [
            event for event in self.events
            if start_time <= event.timestamp <= end_time
        ]
    
    def get_event_count(self) -> int:
        """Get total number of audit events.
        
        Returns:
            Number of events in the chain
        """
        return len(self.events)


if __name__ == "__main__":
    # Example usage
    logger = AuditLogger()
    
    # Log some events
    logger.log_event(
        category="authentication",
        title="User login",
        actor="admin",
        details={"ip": "192.168.1.100", "success": True}
    )
    
    logger.log_event(
        category="key_rotation",
        title="Session key rotated",
        actor="system",
        details={"session_id": "abc123", "robot_id": "dog1"}
    )
    
    # Verify chain integrity
    valid, tampered_index = logger.verify_chain_integrity()
    print(f"Chain valid: {valid}")
    
    # Export compliance report
    report = logger.export_compliance_report(
        start_time=0,
        end_time=time.time(),
        format="json"
    )
    print(f"Exported {len(report)} bytes")
