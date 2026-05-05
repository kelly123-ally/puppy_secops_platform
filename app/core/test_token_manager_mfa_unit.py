"""
Unit tests for Token Manager MFA functionality

Tests MFA enrollment, verification, backup codes, and role enforcement.
Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6
"""

import time
from unittest.mock import Mock

import pyotp
import pytest

from app.core.token_manager import TokenManager, MFACredential


class TestMFAEnrollment:
    """Test MFA enrollment functionality (Requirement 16.1, 16.3)"""
    
    def test_enroll_mfa_generates_totp_secret(self):
        """Test that MFA enrollment generates a valid TOTP secret"""
        token_manager = TokenManager()
        
        totp_secret, qr_code_uri, backup_codes = token_manager.enroll_mfa("user1")
        
        # Verify TOTP secret is base32 encoded
        assert isinstance(totp_secret, str)
        assert len(totp_secret) > 0
        
        # Verify TOTP secret can be used to create TOTP instance
        totp = pyotp.TOTP(totp_secret)
        assert totp is not None
    
    def test_enroll_mfa_generates_qr_code(self):
        """Test that MFA enrollment generates QR code data URI (Requirement 16.3)"""
        token_manager = TokenManager()
        
        totp_secret, qr_code_uri, backup_codes = token_manager.enroll_mfa("user1")
        
        # Verify QR code is a data URI
        assert qr_code_uri.startswith("data:image/png;base64,")
        assert len(qr_code_uri) > 100  # QR code should be substantial
    
    def test_enroll_mfa_generates_backup_codes(self):
        """Test that MFA enrollment generates backup codes (Requirement 16.5)"""
        token_manager = TokenManager()
        
        totp_secret, qr_code_uri, backup_codes = token_manager.enroll_mfa("user1")
        
        # Verify 10 backup codes are generated
        assert len(backup_codes) == 10
        
        # Verify backup codes are unique
        assert len(set(backup_codes)) == 10
        
        # Verify backup codes are hex strings
        for code in backup_codes:
            assert isinstance(code, str)
            assert len(code) == 16  # 8 bytes = 16 hex chars
            int(code, 16)  # Should not raise ValueError
    
    def test_enroll_mfa_stores_credential(self):
        """Test that MFA enrollment stores credential in token manager"""
        token_manager = TokenManager()
        
        totp_secret, qr_code_uri, backup_codes = token_manager.enroll_mfa("user1")
        
        # Verify credential is stored
        assert "user1" in token_manager.mfa_credentials
        
        credential = token_manager.mfa_credentials["user1"]
        assert credential.user == "user1"
        assert credential.totp_secret == totp_secret
        assert credential.backup_codes == backup_codes
        assert credential.enabled is True
        assert credential.created_at > 0
    
    def test_enroll_mfa_logs_to_audit_logger(self):
        """Test that MFA enrollment logs to audit logger"""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        token_manager.enroll_mfa("user1", issuer_name="TestIssuer")
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "authentication"
        assert call_args[1]["title"] == "MFA enrolled"
        assert call_args[1]["actor"] == "user1"
        assert call_args[1]["details"]["issuer"] == "TestIssuer"
        assert call_args[1]["details"]["backup_codes_count"] == 10


class TestMFAVerification:
    """Test MFA verification functionality (Requirement 16.2, 16.4)"""
    
    def test_verify_mfa_with_valid_totp_code(self):
        """Test MFA verification with valid TOTP code (Requirement 16.2)"""
        token_manager = TokenManager()
        
        totp_secret, _, _ = token_manager.enroll_mfa("user1")
        
        # Generate current TOTP code
        totp = pyotp.TOTP(totp_secret)
        current_code = totp.now()
        
        # Verify code
        is_valid = token_manager.verify_mfa("user1", current_code)
        
        assert is_valid is True
    
    def test_verify_mfa_with_invalid_totp_code(self):
        """Test MFA verification with invalid TOTP code (Requirement 16.4)"""
        token_manager = TokenManager()
        
        token_manager.enroll_mfa("user1")
        
        # Use invalid code
        is_valid = token_manager.verify_mfa("user1", "000000")
        
        assert is_valid is False
    
    def test_verify_mfa_with_valid_backup_code(self):
        """Test MFA verification with valid backup code (Requirement 16.5)"""
        token_manager = TokenManager()
        
        _, _, backup_codes = token_manager.enroll_mfa("user1")
        
        # Use first backup code
        backup_code = backup_codes[0]
        is_valid = token_manager.verify_mfa("user1", backup_code)
        
        assert is_valid is True
    
    def test_verify_mfa_removes_used_backup_code(self):
        """Test that used backup codes are removed (Requirement 16.5)"""
        token_manager = TokenManager()
        
        _, _, backup_codes = token_manager.enroll_mfa("user1")
        
        # Use first backup code
        backup_code = backup_codes[0]
        token_manager.verify_mfa("user1", backup_code)
        
        # Verify backup code is removed
        remaining_codes = token_manager.get_backup_codes("user1")
        assert backup_code not in remaining_codes
        assert len(remaining_codes) == 9
    
    def test_verify_mfa_cannot_reuse_backup_code(self):
        """Test that backup codes cannot be reused"""
        token_manager = TokenManager()
        
        _, _, backup_codes = token_manager.enroll_mfa("user1")
        
        # Use first backup code
        backup_code = backup_codes[0]
        first_use = token_manager.verify_mfa("user1", backup_code)
        second_use = token_manager.verify_mfa("user1", backup_code)
        
        assert first_use is True
        assert second_use is False
    
    def test_verify_mfa_with_unenrolled_user(self):
        """Test MFA verification fails for unenrolled user"""
        token_manager = TokenManager()
        
        is_valid = token_manager.verify_mfa("unenrolled_user", "123456")
        
        assert is_valid is False
    
    def test_verify_mfa_with_disabled_mfa(self):
        """Test MFA verification fails when MFA is disabled"""
        token_manager = TokenManager()
        
        totp_secret, _, _ = token_manager.enroll_mfa("user1")
        token_manager.disable_mfa("user1")
        
        # Generate valid TOTP code
        totp = pyotp.TOTP(totp_secret)
        current_code = totp.now()
        
        # Verification should fail because MFA is disabled
        is_valid = token_manager.verify_mfa("user1", current_code)
        
        assert is_valid is False
    
    def test_verify_mfa_logs_success_to_audit_logger(self):
        """Test that successful MFA verification logs to audit logger"""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        totp_secret, _, _ = token_manager.enroll_mfa("user1")
        
        # Clear previous calls
        mock_audit_logger.reset_mock()
        
        # Generate and verify TOTP code
        totp = pyotp.TOTP(totp_secret)
        current_code = totp.now()
        token_manager.verify_mfa("user1", current_code)
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "authentication"
        assert call_args[1]["title"] == "MFA verification succeeded"
        assert call_args[1]["actor"] == "user1"
        assert call_args[1]["details"]["method"] == "totp"
    
    def test_verify_mfa_logs_failure_to_audit_logger(self):
        """Test that failed MFA verification logs to audit logger (Requirement 16.4)"""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        token_manager.enroll_mfa("user1")
        
        # Clear previous calls
        mock_audit_logger.reset_mock()
        
        # Use invalid code
        token_manager.verify_mfa("user1", "000000")
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "authentication"
        assert call_args[1]["title"] == "MFA verification failed"
        assert call_args[1]["actor"] == "user1"


class TestMFAManagement:
    """Test MFA management functionality"""
    
    def test_disable_mfa(self):
        """Test disabling MFA for user"""
        token_manager = TokenManager()
        
        token_manager.enroll_mfa("user1")
        result = token_manager.disable_mfa("user1")
        
        assert result is True
        assert token_manager.is_mfa_enabled("user1") is False
    
    def test_disable_mfa_for_unenrolled_user(self):
        """Test disabling MFA for unenrolled user returns False"""
        token_manager = TokenManager()
        
        result = token_manager.disable_mfa("unenrolled_user")
        
        assert result is False
    
    def test_is_mfa_enabled(self):
        """Test checking if MFA is enabled"""
        token_manager = TokenManager()
        
        # Initially not enabled
        assert token_manager.is_mfa_enabled("user1") is False
        
        # After enrollment
        token_manager.enroll_mfa("user1")
        assert token_manager.is_mfa_enabled("user1") is True
        
        # After disabling
        token_manager.disable_mfa("user1")
        assert token_manager.is_mfa_enabled("user1") is False
    
    def test_get_backup_codes(self):
        """Test getting backup codes for user"""
        token_manager = TokenManager()
        
        _, _, original_codes = token_manager.enroll_mfa("user1")
        retrieved_codes = token_manager.get_backup_codes("user1")
        
        assert retrieved_codes == original_codes
        assert len(retrieved_codes) == 10
    
    def test_get_backup_codes_returns_copy(self):
        """Test that get_backup_codes returns a copy, not reference"""
        token_manager = TokenManager()
        
        token_manager.enroll_mfa("user1")
        codes1 = token_manager.get_backup_codes("user1")
        codes2 = token_manager.get_backup_codes("user1")
        
        # Modify one copy
        codes1.append("new_code")
        
        # Other copy should be unchanged
        assert len(codes2) == 10
    
    def test_get_backup_codes_for_unenrolled_user(self):
        """Test getting backup codes for unenrolled user returns None"""
        token_manager = TokenManager()
        
        codes = token_manager.get_backup_codes("unenrolled_user")
        
        assert codes is None
    
    def test_regenerate_backup_codes(self):
        """Test regenerating backup codes"""
        token_manager = TokenManager()
        
        _, _, original_codes = token_manager.enroll_mfa("user1")
        new_codes = token_manager.regenerate_backup_codes("user1")
        
        # Verify new codes are different
        assert new_codes != original_codes
        assert len(new_codes) == 10
        
        # Verify new codes are stored
        stored_codes = token_manager.get_backup_codes("user1")
        assert stored_codes == new_codes
    
    def test_regenerate_backup_codes_for_unenrolled_user(self):
        """Test regenerating backup codes for unenrolled user returns None"""
        token_manager = TokenManager()
        
        new_codes = token_manager.regenerate_backup_codes("unenrolled_user")
        
        assert new_codes is None
    
    def test_regenerate_backup_codes_logs_to_audit_logger(self):
        """Test that regenerating backup codes logs to audit logger"""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        token_manager.enroll_mfa("user1")
        
        # Clear previous calls
        mock_audit_logger.reset_mock()
        
        token_manager.regenerate_backup_codes("user1")
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "authentication"
        assert call_args[1]["title"] == "MFA backup codes regenerated"
        assert call_args[1]["actor"] == "user1"


class TestMFARoleEnforcement:
    """Test MFA role enforcement functionality (Requirement 16.6)"""
    
    def test_enforce_mfa_for_role(self):
        """Test enforcing MFA for specific role (Requirement 16.6)"""
        token_manager = TokenManager()
        
        token_manager.enforce_mfa_for_role("admin", required=True)
        
        assert token_manager.is_mfa_required_for_role("admin") is True
    
    def test_disable_mfa_requirement_for_role(self):
        """Test disabling MFA requirement for role"""
        token_manager = TokenManager()
        
        token_manager.enforce_mfa_for_role("admin", required=True)
        token_manager.enforce_mfa_for_role("admin", required=False)
        
        assert token_manager.is_mfa_required_for_role("admin") is False
    
    def test_is_mfa_required_for_role_default_false(self):
        """Test that MFA is not required by default for roles"""
        token_manager = TokenManager()
        
        assert token_manager.is_mfa_required_for_role("operator") is False
    
    def test_enforce_mfa_for_multiple_roles(self):
        """Test enforcing MFA for multiple roles"""
        token_manager = TokenManager()
        
        token_manager.enforce_mfa_for_role("admin", required=True)
        token_manager.enforce_mfa_for_role("security_officer", required=True)
        token_manager.enforce_mfa_for_role("operator", required=False)
        
        assert token_manager.is_mfa_required_for_role("admin") is True
        assert token_manager.is_mfa_required_for_role("security_officer") is True
        assert token_manager.is_mfa_required_for_role("operator") is False
    
    def test_enforce_mfa_logs_to_audit_logger(self):
        """Test that enforcing MFA logs to audit logger"""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        token_manager.enforce_mfa_for_role("admin", required=True)
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "authentication"
        assert call_args[1]["title"] == "MFA requirement updated"
        assert call_args[1]["actor"] == "admin"
        assert call_args[1]["details"]["role"] == "admin"
        assert call_args[1]["details"]["required"] is True


class TestMFADataclass:
    """Test MFACredential dataclass"""
    
    def test_mfa_credential_creation(self):
        """Test creating MFACredential"""
        credential = MFACredential(
            user="user1",
            totp_secret="ABCDEFGHIJKLMNOP",
            backup_codes=["code1", "code2"],
            enabled=True,
            created_at=time.time()
        )
        
        assert credential.user == "user1"
        assert credential.totp_secret == "ABCDEFGHIJKLMNOP"
        assert credential.backup_codes == ["code1", "code2"]
        assert credential.enabled is True
        assert credential.created_at > 0
    
    def test_mfa_credential_default_values(self):
        """Test MFACredential default values"""
        credential = MFACredential(
            user="user1",
            totp_secret="ABCDEFGHIJKLMNOP",
            backup_codes=[]
        )
        
        assert credential.enabled is True
        assert credential.created_at == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
