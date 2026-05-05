"""
Token Manager for PuppySecOps Platform

Provides session and token management including:
- Access token issuance with configurable lifetime (5 min - 1 hour)
- Refresh token issuance with configurable lifetime (1 day - 30 days)
- Token refresh with optional rotation
- Token invalidation on logout
- Multi-Factor Authentication (MFA) with TOTP and backup codes

Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 16.1, 16.2, 16.3, 16.4, 16.5, 16.6
"""

from __future__ import annotations

import io
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pyotp
import qrcode


@dataclass
class RefreshToken:
    """Long-lived token used to obtain new access tokens.
    
    Attributes:
        token_id: Unique token identifier
        user: User identifier
        issued_at: Timestamp when token was issued
        expires_at: Timestamp when token expires
        revoked: Whether this token has been revoked
    """
    token_id: str
    user: str
    issued_at: float
    expires_at: float
    revoked: bool = False


@dataclass
class AccessToken:
    """Short-lived token authorizing specific operations.
    
    Attributes:
        token_id: Unique token identifier
        user: User identifier
        issued_at: Timestamp when token was issued
        expires_at: Timestamp when token expires
        refresh_token_id: ID of the refresh token used to obtain this access token
    """
    token_id: str
    user: str
    issued_at: float
    expires_at: float
    refresh_token_id: str


@dataclass
class MFACredential:
    """Multi-Factor Authentication credential for a user.
    
    Attributes:
        user: User identifier
        totp_secret: Base32-encoded TOTP secret key
        backup_codes: List of one-time backup codes for recovery
        enabled: Whether MFA is enabled for this user
        created_at: Timestamp when MFA was enrolled
    """
    user: str
    totp_secret: str
    backup_codes: List[str]
    enabled: bool = True
    created_at: float = 0.0


class TokenManager:
    """Manages access and refresh tokens for user authentication.
    
    Provides token issuance, refresh, and invalidation with configurable
    lifetimes for access and refresh tokens.
    """
    
    def __init__(
        self,
        access_token_lifetime_minutes: int = 15,
        refresh_token_lifetime_days: int = 7,
        rotate_refresh_tokens: bool = True
    ):
        """Initialize Token Manager.
        
        Args:
            access_token_lifetime_minutes: Access token lifetime (5-60 minutes)
            refresh_token_lifetime_days: Refresh token lifetime (1-30 days)
            rotate_refresh_tokens: Whether to rotate refresh tokens on use
            
        Raises:
            ValueError: If lifetimes are out of valid ranges
        """
        # Validate access token lifetime (Requirement 15.2)
        if not 5 <= access_token_lifetime_minutes <= 60:
            raise ValueError(
                "access_token_lifetime_minutes must be between 5 and 60 minutes"
            )
        
        # Validate refresh token lifetime (Requirement 15.3)
        if not 1 <= refresh_token_lifetime_days <= 30:
            raise ValueError(
                "refresh_token_lifetime_days must be between 1 and 30 days"
            )
        
        self.access_token_lifetime_minutes = access_token_lifetime_minutes
        self.refresh_token_lifetime_days = refresh_token_lifetime_days
        self.rotate_refresh_tokens = rotate_refresh_tokens
        
        # Storage for tokens
        self.access_tokens: Dict[str, AccessToken] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}
        
        # Storage for MFA credentials (Requirement 16.1)
        self.mfa_credentials: Dict[str, MFACredential] = {}
        
        # MFA enforcement by role (Requirement 16.6)
        self.mfa_required_roles: Dict[str, bool] = {}
        
        # Audit logger (injected from application)
        self.audit_logger = None  # Set via set_audit_logger()
    
    def issue_access_token(
        self,
        user: str,
        refresh_token_id: str
    ) -> Tuple[str, AccessToken]:
        """Issue access token with configurable lifetime.
        
        Implements Requirement 15.2:
        - Issues access token with lifetime between 5 minutes and 1 hour
        
        Args:
            user: User identifier
            refresh_token_id: ID of refresh token used to obtain this access token
            
        Returns:
            Tuple of (token_id, AccessToken)
        """
        # Generate token ID
        token_id = secrets.token_urlsafe(32)
        
        # Calculate expiration
        now = time.time()
        expires_at = now + (self.access_token_lifetime_minutes * 60)
        
        # Create access token
        access_token = AccessToken(
            token_id=token_id,
            user=user,
            issued_at=now,
            expires_at=expires_at,
            refresh_token_id=refresh_token_id
        )
        
        # Store token
        self.access_tokens[token_id] = access_token
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authentication",
                title="Access token issued",
                actor=user,
                details={
                    "token_id": token_id,
                    "expires_at": expires_at,
                    "lifetime_minutes": self.access_token_lifetime_minutes
                }
            )
        
        return token_id, access_token
    
    def issue_refresh_token(self, user: str) -> Tuple[str, RefreshToken]:
        """Issue refresh token with configurable lifetime.
        
        Implements Requirement 15.3:
        - Issues refresh token with lifetime between 1 day and 30 days
        
        Args:
            user: User identifier
            
        Returns:
            Tuple of (token_id, RefreshToken)
        """
        # Generate token ID
        token_id = secrets.token_urlsafe(32)
        
        # Calculate expiration
        now = time.time()
        expires_at = now + (self.refresh_token_lifetime_days * 24 * 3600)
        
        # Create refresh token
        refresh_token = RefreshToken(
            token_id=token_id,
            user=user,
            issued_at=now,
            expires_at=expires_at,
            revoked=False
        )
        
        # Store token
        self.refresh_tokens[token_id] = refresh_token
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authentication",
                title="Refresh token issued",
                actor=user,
                details={
                    "token_id": token_id,
                    "expires_at": expires_at,
                    "lifetime_days": self.refresh_token_lifetime_days
                }
            )
        
        return token_id, refresh_token
    
    def issue_token_pair(self, user: str) -> Tuple[str, str]:
        """Issue both access and refresh tokens for user authentication.
        
        Implements Requirement 15.1:
        - Issues both access token and refresh token on authentication
        
        Args:
            user: User identifier
            
        Returns:
            Tuple of (access_token_id, refresh_token_id)
        """
        # Issue refresh token first
        refresh_token_id, _ = self.issue_refresh_token(user)
        
        # Issue access token linked to refresh token
        access_token_id, _ = self.issue_access_token(user, refresh_token_id)
        
        return access_token_id, refresh_token_id
    
    def refresh_access_token(
        self,
        refresh_token_id: str
    ) -> Tuple[str, Optional[str]]:
        """Issue new access token using valid refresh token.
        
        Implements Requirements 15.4, 15.5:
        - Accepts valid refresh token to issue new access token
        - Optionally rotates refresh token
        
        Args:
            refresh_token_id: Refresh token to use
            
        Returns:
            Tuple of (new_access_token_id, new_refresh_token_id)
            - new_refresh_token_id is None if rotation is disabled
            
        Raises:
            ValueError: If refresh token is invalid, expired, or revoked
        """
        # Validate refresh token exists
        if refresh_token_id not in self.refresh_tokens:
            raise ValueError("Invalid refresh token")
        
        refresh_token = self.refresh_tokens[refresh_token_id]
        
        # Check if revoked
        if refresh_token.revoked:
            raise ValueError("Refresh token has been revoked")
        
        # Check if expired
        now = time.time()
        if now >= refresh_token.expires_at:
            raise ValueError("Refresh token has expired")
        
        # Issue new access token
        new_access_token_id, _ = self.issue_access_token(
            user=refresh_token.user,
            refresh_token_id=refresh_token_id
        )
        
        # Optionally rotate refresh token (Requirement 15.5)
        new_refresh_token_id = None
        if self.rotate_refresh_tokens:
            # Revoke old refresh token
            refresh_token.revoked = True
            
            # Issue new refresh token
            new_refresh_token_id, _ = self.issue_refresh_token(refresh_token.user)
            
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="authentication",
                    title="Refresh token rotated",
                    actor=refresh_token.user,
                    details={
                        "old_token_id": refresh_token_id,
                        "new_token_id": new_refresh_token_id
                    }
                )
        
        return new_access_token_id, new_refresh_token_id
    
    def invalidate_tokens(self, user: str) -> None:
        """Invalidate all tokens for a user on logout.
        
        Implements Requirement 15.6:
        - Invalidates both access and refresh tokens on logout
        
        Args:
            user: User whose tokens should be invalidated
        """
        # Revoke all refresh tokens for user
        revoked_refresh_count = 0
        for refresh_token in self.refresh_tokens.values():
            if refresh_token.user == user and not refresh_token.revoked:
                refresh_token.revoked = True
                revoked_refresh_count += 1
        
        # Remove all access tokens for user
        removed_access_count = 0
        access_tokens_to_remove = [
            token_id for token_id, token in self.access_tokens.items()
            if token.user == user
        ]
        for token_id in access_tokens_to_remove:
            del self.access_tokens[token_id]
            removed_access_count += 1
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authentication",
                title="User logged out",
                actor=user,
                details={
                    "revoked_refresh_tokens": revoked_refresh_count,
                    "removed_access_tokens": removed_access_count
                }
            )
    
    def validate_access_token(self, token_id: str) -> Tuple[bool, Optional[str]]:
        """Validate access token and return user if valid.
        
        Args:
            token_id: Access token to validate
            
        Returns:
            Tuple of (valid, user)
            - valid: True if token is valid and not expired
            - user: User identifier if valid, None otherwise
        """
        # Check if token exists
        if token_id not in self.access_tokens:
            return False, None
        
        access_token = self.access_tokens[token_id]
        
        # Check if expired
        now = time.time()
        if now >= access_token.expires_at:
            # Remove expired token
            del self.access_tokens[token_id]
            return False, None
        
        return True, access_token.user
    
    def validate_refresh_token(self, token_id: str) -> Tuple[bool, Optional[str]]:
        """Validate refresh token and return user if valid.
        
        Args:
            token_id: Refresh token to validate
            
        Returns:
            Tuple of (valid, user)
            - valid: True if token is valid, not expired, and not revoked
            - user: User identifier if valid, None otherwise
        """
        # Check if token exists
        if token_id not in self.refresh_tokens:
            return False, None
        
        refresh_token = self.refresh_tokens[token_id]
        
        # Check if revoked
        if refresh_token.revoked:
            return False, None
        
        # Check if expired
        now = time.time()
        if now >= refresh_token.expires_at:
            return False, None
        
        return True, refresh_token.user
    
    def cleanup_expired_tokens(self) -> None:
        """Remove expired access tokens and refresh tokens."""
        now = time.time()
        
        # Remove expired access tokens
        expired_access = [
            token_id for token_id, token in self.access_tokens.items()
            if now >= token.expires_at
        ]
        for token_id in expired_access:
            del self.access_tokens[token_id]
        
        # Remove expired refresh tokens
        expired_refresh = [
            token_id for token_id, token in self.refresh_tokens.items()
            if now >= token.expires_at
        ]
        for token_id in expired_refresh:
            del self.refresh_tokens[token_id]
        
        if (expired_access or expired_refresh) and self.audit_logger:
            self.audit_logger.log_event(
                category="token_management",
                title="Expired tokens cleaned up",
                actor="system",
                details={
                    "expired_access_tokens": len(expired_access),
                    "expired_refresh_tokens": len(expired_refresh)
                }
            )
    
    def get_token_stats(self) -> Dict[str, int]:
        """Get statistics about active tokens.
        
        Returns:
            Dictionary with token counts
        """
        now = time.time()
        
        active_access = sum(
            1 for token in self.access_tokens.values()
            if now < token.expires_at
        )
        
        active_refresh = sum(
            1 for token in self.refresh_tokens.values()
            if now < token.expires_at and not token.revoked
        )
        
        return {
            "total_access_tokens": len(self.access_tokens),
            "active_access_tokens": active_access,
            "total_refresh_tokens": len(self.refresh_tokens),
            "active_refresh_tokens": active_refresh
        }
    
    def enroll_mfa(self, user: str, issuer_name: str = "PuppySecOps") -> Tuple[str, str, List[str]]:
        """Enroll user in Multi-Factor Authentication with TOTP.
        
        Implements Requirement 16.1, 16.3:
        - Generates TOTP secret for user
        - Creates QR code for easy enrollment
        - Generates backup codes for recovery
        
        Args:
            user: User identifier
            issuer_name: Name of the issuer for TOTP (appears in authenticator app)
            
        Returns:
            Tuple of (totp_secret, qr_code_data_uri, backup_codes)
            - totp_secret: Base32-encoded secret key
            - qr_code_data_uri: Data URI of QR code image for scanning
            - backup_codes: List of 10 backup codes for recovery
        """
        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        
        # Generate backup codes (Requirement 16.5)
        backup_codes = [secrets.token_hex(8) for _ in range(10)]
        
        # Create MFA credential
        mfa_credential = MFACredential(
            user=user,
            totp_secret=totp_secret,
            backup_codes=backup_codes,
            enabled=True,
            created_at=time.time()
        )
        
        # Store MFA credential
        self.mfa_credentials[user] = mfa_credential
        
        # Generate QR code for TOTP enrollment (Requirement 16.3)
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(
            name=user,
            issuer_name=issuer_name
        )
        
        # Create QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Convert QR code to data URI
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        import base64
        qr_code_data = base64.b64encode(buffer.read()).decode('utf-8')
        qr_code_data_uri = f"data:image/png;base64,{qr_code_data}"
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authentication",
                title="MFA enrolled",
                actor=user,
                details={
                    "issuer": issuer_name,
                    "backup_codes_count": len(backup_codes)
                }
            )
        
        return totp_secret, qr_code_data_uri, backup_codes
    
    def verify_mfa(self, user: str, code: str) -> bool:
        """Verify TOTP code or backup code for user.
        
        Implements Requirement 16.2, 16.4, 16.5:
        - Verifies TOTP code from authenticator app
        - Supports backup codes for recovery
        - Logs verification failures
        
        Args:
            user: User identifier
            code: TOTP code or backup code to verify
            
        Returns:
            True if code is valid, False otherwise
        """
        # Check if user has MFA enrolled
        if user not in self.mfa_credentials:
            return False
        
        mfa_credential = self.mfa_credentials[user]
        
        # Check if MFA is enabled
        if not mfa_credential.enabled:
            return False
        
        # Try TOTP verification first
        totp = pyotp.TOTP(mfa_credential.totp_secret)
        if totp.verify(code, valid_window=1):  # Allow 1 time step tolerance
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="authentication",
                    title="MFA verification succeeded",
                    actor=user,
                    details={"method": "totp"}
                )
            return True
        
        # Try backup code verification (Requirement 16.5)
        if code in mfa_credential.backup_codes:
            # Remove used backup code
            mfa_credential.backup_codes.remove(code)
            
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="authentication",
                    title="MFA verification succeeded",
                    actor=user,
                    details={
                        "method": "backup_code",
                        "remaining_backup_codes": len(mfa_credential.backup_codes)
                    }
                )
            return True
        
        # Verification failed (Requirement 16.4)
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authentication",
                title="MFA verification failed",
                actor=user,
                details={"code_length": len(code)}
            )
        
        return False
    
    def disable_mfa(self, user: str) -> bool:
        """Disable MFA for user.
        
        Args:
            user: User identifier
            
        Returns:
            True if MFA was disabled, False if user had no MFA enrolled
        """
        if user not in self.mfa_credentials:
            return False
        
        self.mfa_credentials[user].enabled = False
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authentication",
                title="MFA disabled",
                actor=user,
                details={}
            )
        
        return True
    
    def is_mfa_enabled(self, user: str) -> bool:
        """Check if MFA is enabled for user.
        
        Args:
            user: User identifier
            
        Returns:
            True if MFA is enabled, False otherwise
        """
        if user not in self.mfa_credentials:
            return False
        
        return self.mfa_credentials[user].enabled
    
    def enforce_mfa_for_role(self, role: str, required: bool = True) -> None:
        """Enforce MFA requirement for specific role.
        
        Implements Requirement 16.6:
        - Allows administrators to enforce MFA for specific roles
        
        Args:
            role: Role identifier (e.g., "admin", "operator")
            required: Whether MFA is required for this role
        """
        self.mfa_required_roles[role] = required
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authentication",
                title="MFA requirement updated",
                actor="admin",
                details={
                    "role": role,
                    "required": required
                }
            )
    
    def is_mfa_required_for_role(self, role: str) -> bool:
        """Check if MFA is required for specific role.
        
        Args:
            role: Role identifier
            
        Returns:
            True if MFA is required for this role, False otherwise
        """
        return self.mfa_required_roles.get(role, False)
    
    def get_backup_codes(self, user: str) -> Optional[List[str]]:
        """Get remaining backup codes for user.
        
        Args:
            user: User identifier
            
        Returns:
            List of remaining backup codes, or None if user has no MFA enrolled
        """
        if user not in self.mfa_credentials:
            return None
        
        return self.mfa_credentials[user].backup_codes.copy()
    
    def regenerate_backup_codes(self, user: str) -> Optional[List[str]]:
        """Regenerate backup codes for user.
        
        Args:
            user: User identifier
            
        Returns:
            List of new backup codes, or None if user has no MFA enrolled
        """
        if user not in self.mfa_credentials:
            return None
        
        # Generate new backup codes
        new_backup_codes = [secrets.token_hex(8) for _ in range(10)]
        self.mfa_credentials[user].backup_codes = new_backup_codes
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authentication",
                title="MFA backup codes regenerated",
                actor=user,
                details={"backup_codes_count": len(new_backup_codes)}
            )
        
        return new_backup_codes.copy()
    
    def set_audit_logger(self, audit_logger) -> None:
        """Set audit logger for logging token management events.
        
        Args:
            audit_logger: AuditLogger instance
        """
        self.audit_logger = audit_logger


if __name__ == "__main__":
    # Example usage
    token_manager = TokenManager(
        access_token_lifetime_minutes=15,
        refresh_token_lifetime_days=7,
        rotate_refresh_tokens=True
    )
    
    # Issue token pair for user
    access_token_id, refresh_token_id = token_manager.issue_token_pair("user1")
    print(f"Access token: {access_token_id}")
    print(f"Refresh token: {refresh_token_id}")
    
    # Validate access token
    valid, user = token_manager.validate_access_token(access_token_id)
    print(f"Access token valid: {valid}, user: {user}")
    
    # Refresh access token
    new_access_token_id, new_refresh_token_id = token_manager.refresh_access_token(
        refresh_token_id
    )
    print(f"New access token: {new_access_token_id}")
    print(f"New refresh token: {new_refresh_token_id}")
    
    # Get token stats
    stats = token_manager.get_token_stats()
    print(f"Token stats: {stats}")
    
    # MFA enrollment example
    print("\n--- MFA Enrollment ---")
    totp_secret, qr_code_uri, backup_codes = token_manager.enroll_mfa("admin_user")
    print(f"TOTP Secret: {totp_secret}")
    print(f"QR Code URI: {qr_code_uri[:50]}...")  # Truncate for display
    print(f"Backup codes: {backup_codes[:3]}...")  # Show first 3
    
    # MFA verification example
    print("\n--- MFA Verification ---")
    import pyotp
    totp = pyotp.TOTP(totp_secret)
    current_code = totp.now()
    print(f"Current TOTP code: {current_code}")
    
    is_valid = token_manager.verify_mfa("admin_user", current_code)
    print(f"MFA verification result: {is_valid}")
    
    # Backup code verification example
    backup_code = backup_codes[0]
    is_valid = token_manager.verify_mfa("admin_user", backup_code)
    print(f"Backup code verification result: {is_valid}")
    
    # Check remaining backup codes
    remaining = token_manager.get_backup_codes("admin_user")
    print(f"Remaining backup codes: {len(remaining)}")
    
    # MFA role enforcement example
    print("\n--- MFA Role Enforcement ---")
    token_manager.enforce_mfa_for_role("admin", required=True)
    print(f"MFA required for admin role: {token_manager.is_mfa_required_for_role('admin')}")
    print(f"MFA required for operator role: {token_manager.is_mfa_required_for_role('operator')}")
    
    # Logout user
    token_manager.invalidate_tokens("user1")
    print("\nUser logged out")
