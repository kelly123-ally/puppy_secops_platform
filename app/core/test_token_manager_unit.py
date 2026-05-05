"""
Unit Tests for Token Manager

Tests specific examples and edge cases for token management functionality.
Tests access tokens, refresh tokens, token pairs, validation, and cleanup.

Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6
"""

import time
from unittest.mock import Mock

import pytest

from app.core.token_manager import TokenManager, AccessToken, RefreshToken


class TestTokenIssuance:
    """Test token issuance functionality."""
    
    def test_issue_access_token(self):
        """Test issuing access token with default lifetime."""
        token_manager = TokenManager(access_token_lifetime_minutes=15)
        
        token_id, access_token = token_manager.issue_access_token("user1", "refresh_123")
        
        # Verify token structure
        assert isinstance(token_id, str)
        assert len(token_id) > 0
        assert isinstance(access_token, AccessToken)
        assert access_token.user == "user1"
        assert access_token.refresh_token_id == "refresh_123"
        
        # Verify expiration is approximately 15 minutes
        expected_expiration = time.time() + (15 * 60)
        assert abs(access_token.expires_at - expected_expiration) < 2
    
    def test_issue_refresh_token(self):
        """Test issuing refresh token with default lifetime."""
        token_manager = TokenManager(refresh_token_lifetime_days=7)
        
        token_id, refresh_token = token_manager.issue_refresh_token("user1")
        
        # Verify token structure
        assert isinstance(token_id, str)
        assert len(token_id) > 0
        assert isinstance(refresh_token, RefreshToken)
        assert refresh_token.user == "user1"
        assert refresh_token.revoked is False
        
        # Verify expiration is approximately 7 days
        expected_expiration = time.time() + (7 * 24 * 3600)
        assert abs(refresh_token.expires_at - expected_expiration) < 2
    
    def test_issue_token_pair(self):
        """Test issuing both access and refresh tokens (Requirement 15.1)."""
        token_manager = TokenManager()
        
        access_token_id, refresh_token_id = token_manager.issue_token_pair("user1")
        
        # Verify both tokens were issued
        assert access_token_id in token_manager.access_tokens
        assert refresh_token_id in token_manager.refresh_tokens
        
        # Verify access token is linked to refresh token
        access_token = token_manager.access_tokens[access_token_id]
        assert access_token.refresh_token_id == refresh_token_id
        assert access_token.user == "user1"
        
        # Verify refresh token
        refresh_token = token_manager.refresh_tokens[refresh_token_id]
        assert refresh_token.user == "user1"
    
    def test_access_token_lifetime_validation(self):
        """Test that access token lifetime is validated (Requirement 15.2)."""
        # Valid lifetimes
        TokenManager(access_token_lifetime_minutes=5)
        TokenManager(access_token_lifetime_minutes=30)
        TokenManager(access_token_lifetime_minutes=60)
        
        # Too short
        with pytest.raises(ValueError, match="between 5 and 60"):
            TokenManager(access_token_lifetime_minutes=4)
        
        # Too long
        with pytest.raises(ValueError, match="between 5 and 60"):
            TokenManager(access_token_lifetime_minutes=61)
    
    def test_refresh_token_lifetime_validation(self):
        """Test that refresh token lifetime is validated (Requirement 15.3)."""
        # Valid lifetimes
        TokenManager(refresh_token_lifetime_days=1)
        TokenManager(refresh_token_lifetime_days=15)
        TokenManager(refresh_token_lifetime_days=30)
        
        # Too short
        with pytest.raises(ValueError, match="between 1 and 30"):
            TokenManager(refresh_token_lifetime_days=0)
        
        # Too long
        with pytest.raises(ValueError, match="between 1 and 30"):
            TokenManager(refresh_token_lifetime_days=31)


class TestAccessTokenExpiration:
    """Test access token expiration behavior."""
    
    def test_access_token_expires_after_lifetime(self):
        """Test that access tokens expire after configured lifetime."""
        # Use very short lifetime for testing
        token_manager = TokenManager(access_token_lifetime_minutes=5)
        
        token_id, access_token = token_manager.issue_access_token("user1", "refresh_123")
        
        # Token should be valid immediately
        valid, user = token_manager.validate_access_token(token_id)
        assert valid is True
        assert user == "user1"
        
        # Manually expire the token
        access_token.expires_at = time.time() - 1
        
        # Token should now be invalid
        valid, user = token_manager.validate_access_token(token_id)
        assert valid is False
        assert user is None
        
        # Expired token should be removed
        assert token_id not in token_manager.access_tokens
    
    def test_access_token_valid_before_expiration(self):
        """Test that access tokens are valid before expiration."""
        token_manager = TokenManager(access_token_lifetime_minutes=15)
        
        token_id, access_token = token_manager.issue_access_token("user1", "refresh_123")
        
        # Set expiration to 5 minutes in the future
        access_token.expires_at = time.time() + (5 * 60)
        
        # Token should be valid
        valid, user = token_manager.validate_access_token(token_id)
        assert valid is True
        assert user == "user1"
    
    def test_validate_nonexistent_access_token(self):
        """Test validating nonexistent access token."""
        token_manager = TokenManager()
        
        valid, user = token_manager.validate_access_token("nonexistent_token")
        
        assert valid is False
        assert user is None


class TestRefreshTokenRotation:
    """Test refresh token rotation behavior."""
    
    def test_refresh_access_token_with_rotation(self):
        """Test refreshing access token with rotation enabled (Requirement 15.5)."""
        token_manager = TokenManager(rotate_refresh_tokens=True)
        
        # Issue initial token pair
        access_token_id, refresh_token_id = token_manager.issue_token_pair("user1")
        
        # Refresh access token
        new_access_token_id, new_refresh_token_id = token_manager.refresh_access_token(
            refresh_token_id
        )
        
        # New access token should be issued
        assert new_access_token_id != access_token_id
        assert new_access_token_id in token_manager.access_tokens
        
        # New refresh token should be issued
        assert new_refresh_token_id is not None
        assert new_refresh_token_id != refresh_token_id
        assert new_refresh_token_id in token_manager.refresh_tokens
        
        # Old refresh token should be revoked
        old_refresh_token = token_manager.refresh_tokens[refresh_token_id]
        assert old_refresh_token.revoked is True
    
    def test_refresh_access_token_without_rotation(self):
        """Test refreshing access token with rotation disabled."""
        token_manager = TokenManager(rotate_refresh_tokens=False)
        
        # Issue initial token pair
        access_token_id, refresh_token_id = token_manager.issue_token_pair("user1")
        
        # Refresh access token
        new_access_token_id, new_refresh_token_id = token_manager.refresh_access_token(
            refresh_token_id
        )
        
        # New access token should be issued
        assert new_access_token_id != access_token_id
        assert new_access_token_id in token_manager.access_tokens
        
        # Refresh token should NOT be rotated
        assert new_refresh_token_id is None
        
        # Old refresh token should still be valid
        old_refresh_token = token_manager.refresh_tokens[refresh_token_id]
        assert old_refresh_token.revoked is False
    
    def test_refresh_with_invalid_token(self):
        """Test that refreshing with invalid token raises error (Requirement 15.4)."""
        token_manager = TokenManager()
        
        with pytest.raises(ValueError, match="Invalid refresh token"):
            token_manager.refresh_access_token("nonexistent_token")
    
    def test_refresh_with_revoked_token(self):
        """Test that refreshing with revoked token raises error."""
        token_manager = TokenManager()
        
        # Issue token pair
        _, refresh_token_id = token_manager.issue_token_pair("user1")
        
        # Revoke refresh token
        token_manager.refresh_tokens[refresh_token_id].revoked = True
        
        # Attempt to refresh
        with pytest.raises(ValueError, match="revoked"):
            token_manager.refresh_access_token(refresh_token_id)
    
    def test_refresh_with_expired_token(self):
        """Test that refreshing with expired token raises error."""
        token_manager = TokenManager()
        
        # Issue token pair
        _, refresh_token_id = token_manager.issue_token_pair("user1")
        
        # Expire refresh token
        token_manager.refresh_tokens[refresh_token_id].expires_at = time.time() - 1
        
        # Attempt to refresh
        with pytest.raises(ValueError, match="expired"):
            token_manager.refresh_access_token(refresh_token_id)


class TestTokenInvalidation:
    """Test token invalidation on logout."""
    
    def test_invalidate_tokens_on_logout(self):
        """Test that all tokens are invalidated on logout (Requirement 15.6)."""
        token_manager = TokenManager()
        
        # Issue multiple token pairs for same user
        access_token_id1, refresh_token_id1 = token_manager.issue_token_pair("user1")
        access_token_id2, refresh_token_id2 = token_manager.issue_token_pair("user1")
        
        # Issue tokens for different user
        access_token_id3, refresh_token_id3 = token_manager.issue_token_pair("user2")
        
        # Invalidate user1's tokens
        token_manager.invalidate_tokens("user1")
        
        # User1's access tokens should be removed
        assert access_token_id1 not in token_manager.access_tokens
        assert access_token_id2 not in token_manager.access_tokens
        
        # User1's refresh tokens should be revoked
        assert token_manager.refresh_tokens[refresh_token_id1].revoked is True
        assert token_manager.refresh_tokens[refresh_token_id2].revoked is True
        
        # User2's tokens should be unaffected
        assert access_token_id3 in token_manager.access_tokens
        assert token_manager.refresh_tokens[refresh_token_id3].revoked is False
    
    def test_invalidate_tokens_for_user_with_no_tokens(self):
        """Test invalidating tokens for user with no tokens."""
        token_manager = TokenManager()
        
        # Should not raise error
        token_manager.invalidate_tokens("user_with_no_tokens")
    
    def test_invalidate_tokens_logs_to_audit_logger(self):
        """Test that token invalidation logs to audit logger."""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        # Issue token pair
        token_manager.issue_token_pair("user1")
        
        # Clear previous calls
        mock_audit_logger.reset_mock()
        
        # Invalidate tokens
        token_manager.invalidate_tokens("user1")
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "authentication"
        assert call_args[1]["title"] == "User logged out"
        assert call_args[1]["actor"] == "user1"
        assert call_args[1]["details"]["revoked_refresh_tokens"] == 1
        assert call_args[1]["details"]["removed_access_tokens"] == 1


class TestTokenValidation:
    """Test token validation functionality."""
    
    def test_validate_valid_access_token(self):
        """Test validating a valid access token."""
        token_manager = TokenManager()
        
        token_id, _ = token_manager.issue_access_token("user1", "refresh_123")
        
        valid, user = token_manager.validate_access_token(token_id)
        
        assert valid is True
        assert user == "user1"
    
    def test_validate_valid_refresh_token(self):
        """Test validating a valid refresh token."""
        token_manager = TokenManager()
        
        token_id, _ = token_manager.issue_refresh_token("user1")
        
        valid, user = token_manager.validate_refresh_token(token_id)
        
        assert valid is True
        assert user == "user1"
    
    def test_validate_nonexistent_refresh_token(self):
        """Test validating nonexistent refresh token."""
        token_manager = TokenManager()
        
        valid, user = token_manager.validate_refresh_token("nonexistent_token")
        
        assert valid is False
        assert user is None
    
    def test_validate_revoked_refresh_token(self):
        """Test validating revoked refresh token."""
        token_manager = TokenManager()
        
        token_id, refresh_token = token_manager.issue_refresh_token("user1")
        refresh_token.revoked = True
        
        valid, user = token_manager.validate_refresh_token(token_id)
        
        assert valid is False
        assert user is None
    
    def test_validate_expired_refresh_token(self):
        """Test validating expired refresh token."""
        token_manager = TokenManager()
        
        token_id, refresh_token = token_manager.issue_refresh_token("user1")
        refresh_token.expires_at = time.time() - 1
        
        valid, user = token_manager.validate_refresh_token(token_id)
        
        assert valid is False
        assert user is None


class TestTokenCleanup:
    """Test token cleanup functionality."""
    
    def test_cleanup_expired_access_tokens(self):
        """Test cleanup of expired access tokens."""
        token_manager = TokenManager()
        
        # Issue tokens
        token_id1, access_token1 = token_manager.issue_access_token("user1", "refresh_1")
        token_id2, access_token2 = token_manager.issue_access_token("user2", "refresh_2")
        
        # Expire first token
        access_token1.expires_at = time.time() - 1
        
        # Cleanup
        token_manager.cleanup_expired_tokens()
        
        # Expired token should be removed
        assert token_id1 not in token_manager.access_tokens
        
        # Valid token should remain
        assert token_id2 in token_manager.access_tokens
    
    def test_cleanup_expired_refresh_tokens(self):
        """Test cleanup of expired refresh tokens."""
        token_manager = TokenManager()
        
        # Issue tokens
        token_id1, refresh_token1 = token_manager.issue_refresh_token("user1")
        token_id2, refresh_token2 = token_manager.issue_refresh_token("user2")
        
        # Expire first token
        refresh_token1.expires_at = time.time() - 1
        
        # Cleanup
        token_manager.cleanup_expired_tokens()
        
        # Expired token should be removed
        assert token_id1 not in token_manager.refresh_tokens
        
        # Valid token should remain
        assert token_id2 in token_manager.refresh_tokens
    
    def test_cleanup_logs_to_audit_logger(self):
        """Test that cleanup logs to audit logger."""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        # Issue and expire tokens
        token_id1, access_token1 = token_manager.issue_access_token("user1", "refresh_1")
        token_id2, refresh_token2 = token_manager.issue_refresh_token("user2")
        
        access_token1.expires_at = time.time() - 1
        refresh_token2.expires_at = time.time() - 1
        
        # Clear previous calls
        mock_audit_logger.reset_mock()
        
        # Cleanup
        token_manager.cleanup_expired_tokens()
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "token_management"
        assert call_args[1]["title"] == "Expired tokens cleaned up"
        assert call_args[1]["actor"] == "system"
        assert call_args[1]["details"]["expired_access_tokens"] == 1
        assert call_args[1]["details"]["expired_refresh_tokens"] == 1
    
    def test_cleanup_with_no_expired_tokens(self):
        """Test cleanup when no tokens are expired."""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        # Issue valid tokens
        token_manager.issue_access_token("user1", "refresh_1")
        token_manager.issue_refresh_token("user2")
        
        # Clear previous calls
        mock_audit_logger.reset_mock()
        
        # Cleanup
        token_manager.cleanup_expired_tokens()
        
        # Audit logger should not be called
        mock_audit_logger.log_event.assert_not_called()


class TestTokenStatistics:
    """Test token statistics functionality."""
    
    def test_get_token_stats(self):
        """Test getting token statistics."""
        token_manager = TokenManager()
        
        # Issue tokens
        token_manager.issue_token_pair("user1")
        token_manager.issue_token_pair("user2")
        
        # Get stats
        stats = token_manager.get_token_stats()
        
        assert stats["total_access_tokens"] == 2
        assert stats["active_access_tokens"] == 2
        assert stats["total_refresh_tokens"] == 2
        assert stats["active_refresh_tokens"] == 2
    
    def test_get_token_stats_with_expired_tokens(self):
        """Test token stats with expired tokens."""
        token_manager = TokenManager()
        
        # Issue tokens
        access_token_id1, _ = token_manager.issue_token_pair("user1")
        access_token_id2, refresh_token_id2 = token_manager.issue_token_pair("user2")
        
        # Expire some tokens
        token_manager.access_tokens[access_token_id1].expires_at = time.time() - 1
        token_manager.refresh_tokens[refresh_token_id2].expires_at = time.time() - 1
        
        # Get stats
        stats = token_manager.get_token_stats()
        
        assert stats["total_access_tokens"] == 2
        assert stats["active_access_tokens"] == 1  # One expired
        assert stats["total_refresh_tokens"] == 2
        assert stats["active_refresh_tokens"] == 1  # One expired
    
    def test_get_token_stats_with_revoked_tokens(self):
        """Test token stats with revoked tokens."""
        token_manager = TokenManager()
        
        # Issue tokens
        _, refresh_token_id1 = token_manager.issue_token_pair("user1")
        token_manager.issue_token_pair("user2")
        
        # Revoke one refresh token
        token_manager.refresh_tokens[refresh_token_id1].revoked = True
        
        # Get stats
        stats = token_manager.get_token_stats()
        
        assert stats["total_refresh_tokens"] == 2
        assert stats["active_refresh_tokens"] == 1  # One revoked


class TestAuditLogging:
    """Test audit logging for token operations."""
    
    def test_issue_access_token_logs_to_audit_logger(self):
        """Test that issuing access token logs to audit logger."""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        token_id, _ = token_manager.issue_access_token("user1", "refresh_123")
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "authentication"
        assert call_args[1]["title"] == "Access token issued"
        assert call_args[1]["actor"] == "user1"
        assert call_args[1]["details"]["token_id"] == token_id
    
    def test_issue_refresh_token_logs_to_audit_logger(self):
        """Test that issuing refresh token logs to audit logger."""
        token_manager = TokenManager()
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        token_id, _ = token_manager.issue_refresh_token("user1")
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called_once()
        call_args = mock_audit_logger.log_event.call_args
        
        assert call_args[1]["category"] == "authentication"
        assert call_args[1]["title"] == "Refresh token issued"
        assert call_args[1]["actor"] == "user1"
        assert call_args[1]["details"]["token_id"] == token_id
    
    def test_refresh_access_token_with_rotation_logs_to_audit_logger(self):
        """Test that token rotation logs to audit logger."""
        token_manager = TokenManager(rotate_refresh_tokens=True)
        mock_audit_logger = Mock()
        token_manager.set_audit_logger(mock_audit_logger)
        
        # Issue initial token pair
        _, refresh_token_id = token_manager.issue_token_pair("user1")
        
        # Clear previous calls
        mock_audit_logger.reset_mock()
        
        # Refresh with rotation
        token_manager.refresh_access_token(refresh_token_id)
        
        # Should log: access token issuance, refresh token issuance, and rotation
        assert mock_audit_logger.log_event.call_count == 3
        
        # Check rotation log
        rotation_call = [
            call for call in mock_audit_logger.log_event.call_args_list
            if call[1]["title"] == "Refresh token rotated"
        ]
        assert len(rotation_call) == 1
        assert rotation_call[0][1]["actor"] == "user1"


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_multiple_token_pairs_for_same_user(self):
        """Test issuing multiple token pairs for same user."""
        token_manager = TokenManager()
        
        # Issue multiple pairs
        access_id1, refresh_id1 = token_manager.issue_token_pair("user1")
        access_id2, refresh_id2 = token_manager.issue_token_pair("user1")
        
        # All tokens should be unique
        assert access_id1 != access_id2
        assert refresh_id1 != refresh_id2
        
        # All should be valid
        assert token_manager.validate_access_token(access_id1)[0] is True
        assert token_manager.validate_access_token(access_id2)[0] is True
        assert token_manager.validate_refresh_token(refresh_id1)[0] is True
        assert token_manager.validate_refresh_token(refresh_id2)[0] is True
    
    def test_token_id_uniqueness(self):
        """Test that token IDs are unique."""
        token_manager = TokenManager()
        
        # Issue many tokens
        token_ids = set()
        for i in range(100):
            access_id, refresh_id = token_manager.issue_token_pair(f"user{i}")
            token_ids.add(access_id)
            token_ids.add(refresh_id)
        
        # All IDs should be unique
        assert len(token_ids) == 200
    
    def test_token_manager_without_audit_logger(self):
        """Test that token manager works without audit logger."""
        token_manager = TokenManager()
        
        # Should not raise error
        token_manager.issue_token_pair("user1")
        token_manager.invalidate_tokens("user1")
        token_manager.cleanup_expired_tokens()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
