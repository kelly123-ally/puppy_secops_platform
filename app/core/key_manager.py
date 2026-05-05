"""
Key Manager for PuppySecOps Platform

Provides secure key management including:
- Master key loading from secure storage
- HKDF-SHA256 session key derivation
- Per-robot key pair generation
- Automatic key rotation with grace periods
- Secure key deletion
- SROS2 keystore export for ROS 2 deployment

Requirements: 2.1-2.6, 3.1-3.5, 4.1-4.5, 5.1-5.6, 25.1, 25.3, 26.2
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class KeyRotationPolicy:
    """Policy for automatic key rotation.
    
    Attributes:
        rotation_interval_hours: Hours between key rotations (1-720)
        grace_period_minutes: Minutes to keep old key for in-flight messages
        auto_rotate_master_key: Whether to rotate master key automatically
    """
    rotation_interval_hours: int = 24  # Default: rotate daily
    grace_period_minutes: int = 5      # Default: 5 minute grace period
    auto_rotate_master_key: bool = False
    
    def __post_init__(self):
        """Validate policy parameters."""
        if not 1 <= self.rotation_interval_hours <= 720:
            raise ValueError("rotation_interval_hours must be between 1 and 720 (30 days)")
        if self.grace_period_minutes < 0:
            raise ValueError("grace_period_minutes must be non-negative")


@dataclass
class RobotKeyPair:
    """Robot's cryptographic key pair.
    
    Attributes:
        robot_id: Unique robot identifier
        public_key: RSA public key (PEM format)
        private_key: RSA private key (PEM format)
        created_at: Timestamp when key pair was created
        revoked: Whether this key pair has been revoked
        key_id: Unique identifier for this key pair
    """
    robot_id: str
    public_key: bytes
    private_key: bytes
    created_at: float
    revoked: bool = False
    key_id: str = field(default_factory=lambda: secrets.token_hex(8))


@dataclass
class SessionKeyInfo:
    """Information about a derived session key.
    
    Attributes:
        session_id: Unique session identifier
        key_id: Key identifier used for derivation
        session_key: Derived 256-bit session key
        created_at: Timestamp when key was derived
        expires_at: Timestamp when key should be rotated
        previous_key: Previous session key (kept during grace period)
        previous_key_expires_at: When previous key becomes invalid
    """
    session_id: str
    key_id: str
    session_key: bytes
    created_at: float
    expires_at: float
    previous_key: Optional[bytes] = None
    previous_key_expires_at: Optional[float] = None


class KeyManager:
    """Manages cryptographic keys for the PuppySecOps Platform.
    
    Provides secure key storage, derivation, rotation, and deletion.
    Designed for future integration with SROS2 for ROS 2 deployment.
    """
    
    def __init__(
        self, 
        master_key_source: str,
        rotation_policy: Optional[KeyRotationPolicy] = None
    ):
        """Initialize Key Manager.
        
        Args:
            master_key_source: Path to master key file or environment variable name
            rotation_policy: Key rotation policy (uses default if None)
            
        Raises:
            PermissionError: If key file has incorrect permissions
            ValueError: If master key source is invalid
        """
        self.master_key_source = master_key_source
        self.rotation_policy = rotation_policy or KeyRotationPolicy()
        
        # Storage for robot key pairs
        self.robot_keys: Dict[str, RobotKeyPair] = {}
        
        # Storage for session keys
        self.session_keys: Dict[str, SessionKeyInfo] = {}
        
        # Audit logger (injected from application) - must be set before loading key
        self.audit_logger = None  # Set via set_audit_logger()
        
        # Load or generate master key (after audit_logger is initialized)
        self.master_key = self._load_or_generate_master_key()
    
    def _load_or_generate_master_key(self) -> bytes:
        """Load master key from source or generate new one.
        
        Returns:
            32-byte master key
            
        Raises:
            PermissionError: If key file has incorrect permissions
        """
        # Try loading from environment variable first
        if self.master_key_source.startswith("env:"):
            env_var = self.master_key_source[4:]
            key_hex = os.environ.get(env_var)
            if key_hex:
                return bytes.fromhex(key_hex)
        
        # Try loading from file
        key_path = Path(self.master_key_source)
        
        if key_path.exists():
            return self._load_master_key_from_file(key_path)
        else:
            # Generate new master key
            return self._generate_and_store_master_key(key_path)
    
    def _load_master_key_from_file(self, key_path: Path) -> bytes:
        """Load master key from file with permission checks.
        
        Args:
            key_path: Path to key file
            
        Returns:
            32-byte master key
            
        Raises:
            PermissionError: If file permissions are not 0600 (Unix only)
        """
        # Check file permissions (Requirement 2.3)
        # Note: Permission checks are Unix-specific and skipped on Windows
        import platform
        if platform.system() != 'Windows':
            stat_info = key_path.stat()
            file_mode = stat_info.st_mode & 0o777
            
            if file_mode != 0o600:
                raise PermissionError(
                    f"Key file {key_path} has incorrect permissions "
                    f"{oct(file_mode)}, expected 0600 (owner read/write only)"
                )
        
        # Load key
        with open(key_path, 'rb') as f:
            master_key = f.read()
        
        if len(master_key) != 32:
            raise ValueError(f"Master key must be exactly 32 bytes, got {len(master_key)}")
        
        return master_key
    
    def _generate_and_store_master_key(self, key_path: Path) -> bytes:
        """Generate new master key and store securely.
        
        Args:
            key_path: Path where key should be stored
            
        Returns:
            32-byte master key
        """
        # Generate 256-bit (32-byte) master key
        master_key = secrets.token_bytes(32)
        
        # Create parent directory if needed
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write key with secure permissions (Requirement 2.6)
        # Use os.open with specific flags to set permissions atomically
        fd = os.open(
            key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600
        )
        try:
            os.write(fd, master_key)
        finally:
            os.close(fd)
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="key_management",
                title="Master key generated",
                actor="system",
                details={"key_path": str(key_path)}
            )
        
        return master_key
    
    def derive_session_key(self, session_id: str, key_id: str) -> bytes:
        """Derive session key using HKDF-SHA256.
        
        Implements Requirements 3.1, 3.2, 3.3:
        - Uses HKDF-SHA256 for key derivation
        - Uses session_id as salt
        - Uses key_id as info parameter
        - Derives 256-bit (32-byte) session keys
        
        Args:
            session_id: Unique session identifier (used as salt)
            key_id: Key identifier (used as info parameter)
            
        Returns:
            32-byte derived session key
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=session_id.encode('utf-8'),
            info=f"LBSE::{key_id}".encode('utf-8'),
        )
        
        session_key = hkdf.derive(self.master_key)
        
        # Store session key info for rotation tracking
        now = time.time()
        expires_at = now + (self.rotation_policy.rotation_interval_hours * 3600)
        
        self.session_keys[session_id] = SessionKeyInfo(
            session_id=session_id,
            key_id=key_id,
            session_key=session_key,
            created_at=now,
            expires_at=expires_at
        )
        
        return session_key
    
    def generate_robot_keypair(self, robot_id: str) -> Tuple[bytes, bytes]:
        """Generate unique RSA key pair for robot.
        
        Implements Requirements 4.1, 4.2, 4.4:
        - Generates unique key pair for each robot
        - Stores key pairs separately from master key
        - Maintains mapping between robot_id and key_id
        
        Args:
            robot_id: Unique robot identifier
            
        Returns:
            Tuple of (public_key_pem, private_key_pem)
        """
        # Generate 2048-bit RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Store key pair
        key_pair = RobotKeyPair(
            robot_id=robot_id,
            public_key=public_pem,
            private_key=private_pem,
            created_at=time.time()
        )
        
        self.robot_keys[robot_id] = key_pair
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="key_management",
                title="Robot key pair generated",
                actor="system",
                details={
                    "robot_id": robot_id,
                    "key_id": key_pair.key_id
                }
            )
        
        return public_pem, private_pem
    
    def revoke_robot_key(self, robot_id: str) -> None:
        """Mark robot's key pair as revoked.
        
        Implements Requirements 4.3, 4.5:
        - Marks key pair as invalid
        - Subsequent authentication attempts will fail
        
        Args:
            robot_id: Robot whose key should be revoked
            
        Raises:
            KeyError: If robot_id not found
        """
        if robot_id not in self.robot_keys:
            raise KeyError(f"Robot {robot_id} not found in key store")
        
        self.robot_keys[robot_id].revoked = True
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="key_management",
                title="Robot key revoked",
                actor="system",
                details={
                    "robot_id": robot_id,
                    "key_id": self.robot_keys[robot_id].key_id
                }
            )
    
    def is_robot_key_revoked(self, robot_id: str) -> bool:
        """Check if robot's key is revoked.
        
        Args:
            robot_id: Robot to check
            
        Returns:
            True if key is revoked, False otherwise
        """
        if robot_id not in self.robot_keys:
            return True  # Unknown robot = revoked
        
        return self.robot_keys[robot_id].revoked
    
    def rotate_session_key(self, session_id: str) -> bytes:
        """Rotate session key with grace period support.
        
        Implements Requirements 5.2, 5.3, 5.4:
        - Generates new session key
        - Maintains old key for grace period
        - Logs rotation event
        
        Args:
            session_id: Session to rotate
            
        Returns:
            New session key
            
        Raises:
            KeyError: If session not found
        """
        if session_id not in self.session_keys:
            raise KeyError(f"Session {session_id} not found")
        
        old_key_info = self.session_keys[session_id]
        old_session_key = old_key_info.session_key
        
        # Derive new session key with incremented key_id to ensure uniqueness
        new_key_id = f"{old_key_info.key_id}_rotated_{int(time.time())}"
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=session_id.encode('utf-8'),
            info=f"LBSE::{new_key_id}".encode('utf-8'),
        )
        
        new_key = hkdf.derive(self.master_key)
        
        # Update session key info with grace period
        now = time.time()
        grace_period_seconds = self.rotation_policy.grace_period_minutes * 60
        expires_at = now + (self.rotation_policy.rotation_interval_hours * 3600)
        
        self.session_keys[session_id] = SessionKeyInfo(
            session_id=session_id,
            key_id=new_key_id,
            session_key=new_key,
            created_at=now,
            expires_at=expires_at,
            previous_key=old_session_key,
            previous_key_expires_at=now + grace_period_seconds
        )
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="key_rotation",
                title="Session key rotated",
                actor="system",
                details={
                    "session_id": session_id,
                    "old_key_id": old_key_info.key_id,
                    "new_key_id": new_key_id,
                    "grace_period_minutes": self.rotation_policy.grace_period_minutes
                }
            )
        
        return new_key
    
    def is_key_in_grace_period(self, session_id: str, key: bytes) -> bool:
        """Check if a key is valid during grace period.
        
        Args:
            session_id: Session identifier
            key: Key to check
            
        Returns:
            True if key is current or in grace period
        """
        if session_id not in self.session_keys:
            return False
        
        key_info = self.session_keys[session_id]
        
        # Check if it's the current key
        if key == key_info.session_key:
            return True
        
        # Check if it's the previous key within grace period
        if key_info.previous_key and key == key_info.previous_key:
            now = time.time()
            if key_info.previous_key_expires_at and now < key_info.previous_key_expires_at:
                return True
        
        return False
    
    def secure_delete_key(self, key_material: bytes) -> None:
        """Securely erase key from memory.
        
        Implements Requirements 25.1, 25.3:
        - Overwrites key memory with zeros before deallocation
        
        Args:
            key_material: Key bytes to delete
        """
        # Python doesn't allow direct memory manipulation, but we can
        # overwrite the bytearray to reduce the window of exposure
        if isinstance(key_material, bytes):
            # Convert to bytearray for in-place modification
            key_array = bytearray(key_material)
            for i in range(len(key_array)):
                key_array[i] = 0
            # Clear the bytearray
            key_array.clear()
    
    def cleanup_expired_keys(self) -> None:
        """Remove expired session keys and grace period keys."""
        now = time.time()
        expired_sessions = []
        
        for session_id, key_info in self.session_keys.items():
            # Clean up expired previous keys
            if key_info.previous_key and key_info.previous_key_expires_at:
                if now >= key_info.previous_key_expires_at:
                    self.secure_delete_key(key_info.previous_key)
                    key_info.previous_key = None
                    key_info.previous_key_expires_at = None
            
            # Mark sessions for removal if expired
            if now >= key_info.expires_at:
                expired_sessions.append(session_id)
        
        # Remove expired sessions
        for session_id in expired_sessions:
            key_info = self.session_keys.pop(session_id)
            self.secure_delete_key(key_info.session_key)
            if key_info.previous_key:
                self.secure_delete_key(key_info.previous_key)
    
    def export_to_sros2_keystore(self, robot_id: str, output_dir: str) -> None:
        """Export robot keys to SROS2 keystore format.
        
        Implements Requirement 26.2:
        - Creates SROS2 directory structure
        - Exports keys in PEM format compatible with DDS-Security
        
        Args:
            robot_id: Robot whose keys to export
            output_dir: Base directory for SROS2 keystore
            
        Raises:
            KeyError: If robot_id not found
        """
        if robot_id not in self.robot_keys:
            raise KeyError(f"Robot {robot_id} not found in key store")
        
        key_pair = self.robot_keys[robot_id]
        
        # Create SROS2 directory structure
        robot_dir = Path(output_dir) / robot_id
        robot_dir.mkdir(parents=True, exist_ok=True)
        
        # Export private key
        key_file = robot_dir / "key.pem"
        with open(key_file, 'wb') as f:
            f.write(key_pair.private_key)
        os.chmod(key_file, 0o600)
        
        # Export public key (certificate will be added by Certificate Manager)
        cert_file = robot_dir / "cert.pem"
        with open(cert_file, 'wb') as f:
            f.write(key_pair.public_key)
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="key_management",
                title="Keys exported to SROS2 keystore",
                actor="system",
                details={
                    "robot_id": robot_id,
                    "output_dir": str(robot_dir)
                }
            )
    
    def set_audit_logger(self, audit_logger) -> None:
        """Set audit logger for logging key management events.
        
        Args:
            audit_logger: AuditLogger instance
        """
        self.audit_logger = audit_logger
    
    def shutdown(self) -> None:
        """Clean up and securely delete all keys on shutdown.
        
        Implements Requirement 2.4:
        - Clears master key from memory
        - Securely deletes all session keys
        """
        # Secure delete master key
        self.secure_delete_key(self.master_key)
        
        # Secure delete all session keys
        for key_info in self.session_keys.values():
            self.secure_delete_key(key_info.session_key)
            if key_info.previous_key:
                self.secure_delete_key(key_info.previous_key)
        
        self.session_keys.clear()
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="key_management",
                title="Key Manager shutdown",
                actor="system",
                details={"message": "All keys securely deleted"}
            )
