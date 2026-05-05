"""
Unit Tests for Access Controller

Tests specific examples and edge cases for access control and rate limiting.

Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 14.1, 14.2, 14.3, 14.4, 14.5
"""

import time

import pytest

from app.core.access_controller import (
    AccessController,
    Permission,
    RateLimitPolicy,
    Role,
    ADMIN_ROLE,
    OPERATOR_ROLE,
    ROBOT_ROLE,
)


class TestPermissionChecks:
    """Test permission checking functionality."""
    
    def test_check_permission_allowed(self):
        """Test that actor with permission is allowed."""
        controller = AccessController()
        
        # Grant permission
        controller.grant_permission(
            actor="user1",
            permission=Permission(name="robot:control", resource_pattern="robot:dog1")
        )
        
        # Check permission
        allowed, reason = controller.check_permission(
            actor="user1",
            action="robot:control",
            resource="robot:dog1"
        )
        
        assert allowed
        assert reason == "Allowed"
    
    def test_check_permission_denied(self):
        """Test that actor without permission is denied."""
        controller = AccessController()
        
        # No permissions granted
        allowed, reason = controller.check_permission(
            actor="user1",
            action="robot:control",
            resource="robot:dog1"
        )
        
        assert not allowed
        assert "Permission denied" in reason
    
    def test_check_permission_wildcard_action(self):
        """Test wildcard action permission."""
        controller = AccessController()
        
        # Grant wildcard permission
        controller.grant_permission(
            actor="admin",
            permission=Permission(name="*", resource_pattern="*")
        )
        
        # Should allow any action
        allowed, _ = controller.check_permission(
            actor="admin",
            action="robot:control",
            resource="robot:dog1"
        )
        assert allowed
        
        allowed, _ = controller.check_permission(
            actor="admin",
            action="task:create",
            resource="task:123"
        )
        assert allowed
    
    def test_check_permission_wildcard_resource(self):
        """Test wildcard resource permission."""
        controller = AccessController()
        
        # Grant permission with wildcard resource
        controller.grant_permission(
            actor="operator",
            permission=Permission(name="robot:control", resource_pattern="*")
        )
        
        # Should allow any resource
        allowed, _ = controller.check_permission(
            actor="operator",
            action="robot:control",
            resource="robot:dog1"
        )
        assert allowed
        
        allowed, _ = controller.check_permission(
            actor="operator",
            action="robot:control",
            resource="robot:dog2"
        )
        assert allowed
    
    def test_check_permission_resource_prefix_match(self):
        """Test resource pattern prefix matching."""
        controller = AccessController()
        
        # Grant permission with prefix pattern
        controller.grant_permission(
            actor="user1",
            permission=Permission(name="robot:control", resource_pattern="robot:*")
        )
        
        # Should match resources with prefix
        allowed, _ = controller.check_permission(
            actor="user1",
            action="robot:control",
            resource="robot:dog1"
        )
        assert allowed
        
        allowed, _ = controller.check_permission(
            actor="user1",
            action="robot:control",
            resource="robot:dog2"
        )
        assert allowed
        
        # Should not match different prefix
        allowed, _ = controller.check_permission(
            actor="user1",
            action="robot:control",
            resource="task:123"
        )
        assert not allowed
    
    def test_check_permission_exact_resource_match(self):
        """Test exact resource matching."""
        controller = AccessController()
        
        # Grant permission for specific resource
        controller.grant_permission(
            actor="user1",
            permission=Permission(name="robot:control", resource_pattern="robot:dog1")
        )
        
        # Should allow exact match
        allowed, _ = controller.check_permission(
            actor="user1",
            action="robot:control",
            resource="robot:dog1"
        )
        assert allowed
        
        # Should deny different resource
        allowed, _ = controller.check_permission(
            actor="user1",
            action="robot:control",
            resource="robot:dog2"
        )
        assert not allowed
    
    def test_check_permission_no_resource_specified(self):
        """Test permission check without resource."""
        controller = AccessController()
        
        # Grant permission without resource pattern
        controller.grant_permission(
            actor="user1",
            permission=Permission(name="audit:read")
        )
        
        # Should allow action without resource
        allowed, _ = controller.check_permission(
            actor="user1",
            action="audit:read",
            resource=None
        )
        assert allowed


class TestRoleBasedPermissions:
    """Test role-based permission inheritance."""
    
    def test_assign_role(self):
        """Test assigning role to actor."""
        controller = AccessController()
        
        # Add role
        controller.add_role(OPERATOR_ROLE)
        
        # Assign role
        controller.assign_role("user1", "operator")
        
        assert "user1" in controller.actor_roles
        assert "operator" in controller.actor_roles["user1"]
    
    def test_assign_nonexistent_role(self):
        """Test that assigning nonexistent role raises error."""
        controller = AccessController()
        
        with pytest.raises(KeyError, match="not found"):
            controller.assign_role("user1", "nonexistent")
    
    def test_role_permission_inheritance(self):
        """Test that actors inherit permissions from roles."""
        controller = AccessController()
        
        # Add role with permissions
        controller.add_role(OPERATOR_ROLE)
        controller.assign_role("user1", "operator")
        
        # Check inherited permission
        allowed, _ = controller.check_permission(
            actor="user1",
            action="robot:control",
            resource="robot:dog1"
        )
        assert allowed
    
    def test_multiple_role_inheritance(self):
        """Test inheriting permissions from multiple roles."""
        controller = AccessController()
        
        # Create custom roles
        role1 = Role(
            name="role1",
            permissions=[Permission(name="action1", resource_pattern="*")]
        )
        role2 = Role(
            name="role2",
            permissions=[Permission(name="action2", resource_pattern="*")]
        )
        
        controller.add_role(role1)
        controller.add_role(role2)
        
        # Assign both roles
        controller.assign_role("user1", "role1")
        controller.assign_role("user1", "role2")
        
        # Should have permissions from both roles
        allowed, _ = controller.check_permission("user1", "action1", "resource1")
        assert allowed
        
        allowed, _ = controller.check_permission("user1", "action2", "resource2")
        assert allowed
    
    def test_direct_and_role_permissions_combined(self):
        """Test that direct and role permissions are combined."""
        controller = AccessController()
        
        # Add role
        controller.add_role(ROBOT_ROLE)
        controller.assign_role("robot1", "robot")
        
        # Grant additional direct permission
        controller.grant_permission(
            actor="robot1",
            permission=Permission(name="special:action", resource_pattern="*")
        )
        
        # Should have role permissions
        allowed, _ = controller.check_permission("robot1", "task:read", "task:123")
        assert allowed
        
        # Should have direct permission
        allowed, _ = controller.check_permission("robot1", "special:action", "resource1")
        assert allowed
    
    def test_get_actor_permissions_no_duplicates(self):
        """Test that get_actor_permissions returns no duplicates."""
        controller = AccessController()
        
        # Grant same permission directly and via role
        perm = Permission(name="test:action", resource_pattern="*")
        
        role = Role(name="test_role", permissions=[perm])
        controller.add_role(role)
        controller.assign_role("user1", "test_role")
        controller.grant_permission("user1", perm)
        
        # Get permissions
        permissions = controller.get_actor_permissions("user1")
        
        # Should only appear once
        matching = [p for p in permissions if p.name == "test:action"]
        assert len(matching) == 1


class TestTemporaryPermissions:
    """Test temporary permission grants with expiration."""
    
    def test_grant_temporary_permission(self):
        """Test granting temporary permission."""
        controller = AccessController()
        
        # Grant temporary permission (expires in 1 hour)
        expires_at = time.time() + 3600
        controller.grant_temporary_permission(
            actor="user1",
            permission=Permission(name="emergency:access", resource_pattern="*"),
            expires_at=expires_at
        )
        
        # Should be allowed before expiration
        allowed, _ = controller.check_permission("user1", "emergency:access", "resource1")
        assert allowed
    
    def test_temporary_permission_expiration(self):
        """Test that temporary permissions expire."""
        controller = AccessController()
        
        # Grant temporary permission that expires immediately
        expires_at = time.time() - 1  # Already expired
        controller.grant_temporary_permission(
            actor="user1",
            permission=Permission(name="emergency:access", resource_pattern="*"),
            expires_at=expires_at
        )
        
        # Should be denied after expiration
        allowed, _ = controller.check_permission("user1", "emergency:access", "resource1")
        assert not allowed
    
    def test_temporary_permission_cleanup(self):
        """Test that expired temporary permissions are cleaned up."""
        controller = AccessController()
        
        # Grant expired temporary permission
        expires_at = time.time() - 1
        controller.grant_temporary_permission(
            actor="user1",
            permission=Permission(name="temp:action", resource_pattern="*"),
            expires_at=expires_at
        )
        
        # Access permissions (triggers cleanup)
        permissions = controller.get_actor_permissions("user1")
        
        # Expired permission should be removed
        assert "user1" not in controller.temporary_permissions or \
               len(controller.temporary_permissions["user1"]) == 0
    
    def test_multiple_temporary_permissions(self):
        """Test multiple temporary permissions with different expirations."""
        controller = AccessController()
        
        # Grant two temporary permissions
        expires_soon = time.time() - 1  # Expired
        expires_later = time.time() + 3600  # Valid
        
        controller.grant_temporary_permission(
            actor="user1",
            permission=Permission(name="action1", resource_pattern="*"),
            expires_at=expires_soon
        )
        controller.grant_temporary_permission(
            actor="user1",
            permission=Permission(name="action2", resource_pattern="*"),
            expires_at=expires_later
        )
        
        # First should be denied
        allowed, _ = controller.check_permission("user1", "action1", "resource1")
        assert not allowed
        
        # Second should be allowed
        allowed, _ = controller.check_permission("user1", "action2", "resource2")
        assert allowed


class TestRateLimiting:
    """Test API rate limiting functionality."""
    
    def test_rate_limit_within_limit(self):
        """Test requests within rate limit are allowed."""
        controller = AccessController()
        
        # Add rate limit policy: 5 requests per 10 seconds
        policy = RateLimitPolicy(
            endpoint_pattern="/api/tasks",
            requests_per_window=5,
            window_seconds=10
        )
        controller.add_rate_limit_policy(policy)
        
        # Make 5 requests
        for i in range(5):
            allowed, retry_after = controller.check_rate_limit(
                client_id="client1",
                endpoint="/api/tasks"
            )
            assert allowed
            assert retry_after == 0.0
    
    def test_rate_limit_exceeded(self):
        """Test that exceeding rate limit is blocked."""
        controller = AccessController()
        
        # Add rate limit policy: 3 requests per 10 seconds
        policy = RateLimitPolicy(
            endpoint_pattern="/api/tasks",
            requests_per_window=3,
            window_seconds=10
        )
        controller.add_rate_limit_policy(policy)
        
        # Make 3 requests (should succeed)
        for i in range(3):
            allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
            assert allowed
        
        # 4th request should be blocked
        allowed, retry_after = controller.check_rate_limit("client1", "/api/tasks")
        assert not allowed
        assert retry_after > 0.0
    
    def test_rate_limit_reset(self):
        """Test that rate limit resets after time window."""
        controller = AccessController()
        
        # Add rate limit policy: 2 requests per 1 second
        policy = RateLimitPolicy(
            endpoint_pattern="/api/tasks",
            requests_per_window=2,
            window_seconds=1
        )
        controller.add_rate_limit_policy(policy)
        
        # Make 2 requests
        for i in range(2):
            allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
            assert allowed
        
        # 3rd request should be blocked
        allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
        assert not allowed
        
        # Wait for window to reset
        time.sleep(1.1)
        
        # Should be allowed again
        allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
        assert allowed
    
    def test_rate_limit_per_client(self):
        """Test that rate limits are enforced per client."""
        controller = AccessController()
        
        # Add rate limit policy: 2 requests per 10 seconds
        policy = RateLimitPolicy(
            endpoint_pattern="/api/tasks",
            requests_per_window=2,
            window_seconds=10
        )
        controller.add_rate_limit_policy(policy)
        
        # Client1 makes 2 requests
        for i in range(2):
            allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
            assert allowed
        
        # Client1 is blocked
        allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
        assert not allowed
        
        # Client2 should still be allowed
        allowed, _ = controller.check_rate_limit("client2", "/api/tasks")
        assert allowed
    
    def test_rate_limit_different_endpoints(self):
        """Test different rate limits for different endpoints."""
        controller = AccessController()
        
        # Add policies for different endpoints
        policy1 = RateLimitPolicy(
            endpoint_pattern="/api/tasks",
            requests_per_window=5,
            window_seconds=10
        )
        policy2 = RateLimitPolicy(
            endpoint_pattern="/api/robots",
            requests_per_window=10,
            window_seconds=10
        )
        
        controller.add_rate_limit_policy(policy1)
        controller.add_rate_limit_policy(policy2)
        
        # Make 5 requests to /api/tasks
        for i in range(5):
            allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
            assert allowed
        
        # 6th request to /api/tasks should be blocked
        allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
        assert not allowed
        
        # But /api/robots should still be allowed
        allowed, _ = controller.check_rate_limit("client1", "/api/robots")
        assert allowed
    
    def test_rate_limit_no_policy(self):
        """Test that endpoints without policy have no limit."""
        controller = AccessController()
        
        # No policy added
        
        # Should allow unlimited requests
        for i in range(100):
            allowed, retry_after = controller.check_rate_limit(
                client_id="client1",
                endpoint="/api/unlimited"
            )
            assert allowed
            assert retry_after == 0.0
    
    def test_rate_limit_wildcard_endpoint(self):
        """Test rate limit with wildcard endpoint pattern."""
        controller = AccessController()
        
        # Add policy with wildcard
        policy = RateLimitPolicy(
            endpoint_pattern="/api/*",
            requests_per_window=3,
            window_seconds=10
        )
        controller.add_rate_limit_policy(policy)
        
        # Should match any /api/* endpoint
        for i in range(3):
            allowed, _ = controller.check_rate_limit("client1", "/api/tasks")
            assert allowed
        
        # 4th request should be blocked
        allowed, _ = controller.check_rate_limit("client1", "/api/robots")
        assert not allowed


class TestRoleSpecificRateLimits:
    """Test role-specific rate limit overrides."""
    
    def test_role_specific_rate_limit_override(self):
        """Test that roles can have different rate limits."""
        controller = AccessController()
        
        # Add policy with role overrides
        policy = RateLimitPolicy(
            endpoint_pattern="/api/tasks",
            requests_per_window=5,  # Default
            window_seconds=10,
            role_overrides={
                "admin": 100,  # Admins get higher limit
                "robot": 2     # Robots get lower limit
            }
        )
        controller.add_rate_limit_policy(policy)
        
        # Regular user: 5 requests
        for i in range(5):
            allowed, _ = controller.check_rate_limit(
                client_id="user1",
                endpoint="/api/tasks",
                actor_roles=None
            )
            assert allowed
        
        allowed, _ = controller.check_rate_limit("user1", "/api/tasks", None)
        assert not allowed
        
        # Admin: 100 requests
        for i in range(100):
            allowed, _ = controller.check_rate_limit(
                client_id="admin1",
                endpoint="/api/tasks",
                actor_roles=["admin"]
            )
            assert allowed
        
        # Robot: 2 requests
        for i in range(2):
            allowed, _ = controller.check_rate_limit(
                client_id="robot1",
                endpoint="/api/tasks",
                actor_roles=["robot"]
            )
            assert allowed
        
        allowed, _ = controller.check_rate_limit(
            "robot1",
            "/api/tasks",
            ["robot"]
        )
        assert not allowed
    
    def test_role_override_first_role_wins(self):
        """Test that first matching role override is used."""
        controller = AccessController()
        
        # Add policy with role overrides
        policy = RateLimitPolicy(
            endpoint_pattern="/api/tasks",
            requests_per_window=5,
            window_seconds=10,
            role_overrides={
                "admin": 100,
                "operator": 20
            }
        )
        controller.add_rate_limit_policy(policy)
        
        # User with multiple roles - first match wins
        for i in range(100):
            allowed, _ = controller.check_rate_limit(
                client_id="user1",
                endpoint="/api/tasks",
                actor_roles=["admin", "operator"]
            )
            assert allowed


class TestAuditLogging:
    """Test audit logging integration."""
    
    def test_permission_denial_logged(self):
        """Test that permission denials are logged."""
        from app.core.audit_logger import AuditLogger
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create audit logger
            audit_logger = AuditLogger(
                signing_key_path=str(Path(tmpdir) / "key.pem"),
                genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
                storage_path=str(Path(tmpdir) / "events.json")
            )
            
            # Create controller with audit logger
            controller = AccessController()
            controller.set_audit_logger(audit_logger)
            
            # Attempt denied action
            controller.check_permission("user1", "forbidden:action", "resource1")
            
            # Check audit log
            assert len(audit_logger.events) == 1
            assert audit_logger.events[0].category == "authorization"
            assert audit_logger.events[0].title == "Permission denied"
            assert audit_logger.events[0].actor == "user1"
    
    def test_rate_limit_violation_logged(self):
        """Test that rate limit violations are logged."""
        from app.core.audit_logger import AuditLogger
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create audit logger
            audit_logger = AuditLogger(
                signing_key_path=str(Path(tmpdir) / "key.pem"),
                genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
                storage_path=str(Path(tmpdir) / "events.json")
            )
            
            # Create controller with audit logger
            controller = AccessController()
            controller.set_audit_logger(audit_logger)
            
            # Add rate limit policy
            policy = RateLimitPolicy(
                endpoint_pattern="/api/tasks",
                requests_per_window=2,
                window_seconds=10
            )
            controller.add_rate_limit_policy(policy)
            
            # Exceed rate limit
            controller.check_rate_limit("client1", "/api/tasks")
            controller.check_rate_limit("client1", "/api/tasks")
            controller.check_rate_limit("client1", "/api/tasks")  # This exceeds
            
            # Check audit log
            rate_limit_events = [e for e in audit_logger.events if e.category == "rate_limit"]
            assert len(rate_limit_events) == 1
            assert rate_limit_events[0].title == "Rate limit exceeded"
            assert rate_limit_events[0].actor == "client1"


class TestPredefinedRoles:
    """Test predefined role definitions."""
    
    def test_admin_role_has_wildcard_permissions(self):
        """Test that admin role has wildcard permissions."""
        controller = AccessController()
        controller.add_role(ADMIN_ROLE)
        controller.assign_role("admin1", "admin")
        
        # Admin should be allowed everything
        allowed, _ = controller.check_permission("admin1", "any:action", "any:resource")
        assert allowed
    
    def test_operator_role_permissions(self):
        """Test operator role has expected permissions."""
        controller = AccessController()
        controller.add_role(OPERATOR_ROLE)
        controller.assign_role("operator1", "operator")
        
        # Should have robot control
        allowed, _ = controller.check_permission("operator1", "robot:control", "robot:dog1")
        assert allowed
        
        # Should have task create
        allowed, _ = controller.check_permission("operator1", "task:create", "task:123")
        assert allowed
        
        # Should have audit read
        allowed, _ = controller.check_permission("operator1", "audit:read", None)
        assert allowed
    
    def test_robot_role_permissions(self):
        """Test robot role has expected permissions."""
        controller = AccessController()
        controller.add_role(ROBOT_ROLE)
        controller.assign_role("robot1", "robot")
        
        # Should have task read
        allowed, _ = controller.check_permission("robot1", "task:read", "task:123")
        assert allowed
        
        # Should have telemetry write
        allowed, _ = controller.check_permission("robot1", "telemetry:write", "data")
        assert allowed
        
        # Should not have robot control
        allowed, _ = controller.check_permission("robot1", "robot:control", "robot:dog2")
        assert not allowed


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
