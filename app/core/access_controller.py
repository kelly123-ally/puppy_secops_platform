"""
Access Controller for PuppySecOps Platform

Provides fine-grained access control including:
- Permission and role-based access control
- API rate limiting with token bucket algorithm
- Temporary permission grants
- Permission inheritance through roles

Requirements: 13.1-13.6, 14.1-14.6
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Permission:
    """Fine-grained permission definition.
    
    Attributes:
        name: Permission name (e.g., "robot:control", "task:create")
        resource_pattern: Optional resource pattern (e.g., "robot:dog1", "task:*")
    """
    name: str
    resource_pattern: Optional[str] = None


@dataclass
class Role:
    """Role with associated permissions.
    
    Attributes:
        name: Role name (e.g., "admin", "operator", "robot")
        permissions: List of permissions granted to this role
    """
    name: str
    permissions: List[Permission] = field(default_factory=list)


@dataclass
class RateLimitPolicy:
    """Rate limiting policy for API endpoints.
    
    Attributes:
        endpoint_pattern: Endpoint pattern (e.g., "/api/tasks/*")
        requests_per_window: Maximum requests allowed per window
        window_seconds: Time window in seconds
        role_overrides: Role-specific limits (role_name -> requests_per_window)
    """
    endpoint_pattern: str
    requests_per_window: int
    window_seconds: int
    role_overrides: Dict[str, int] = field(default_factory=dict)


@dataclass
class TokenBucket:
    """Token bucket for rate limiting.
    
    Attributes:
        capacity: Maximum tokens (requests) allowed
        tokens: Current available tokens
        last_refill: Timestamp of last refill
        refill_rate: Tokens added per second
    """
    capacity: int
    tokens: float
    last_refill: float
    refill_rate: float


class AccessController:
    """Enforces fine-grained permissions and API rate limiting."""
    
    def __init__(self):
        """Initialize Access Controller."""
        # Permission storage
        self.actor_permissions: Dict[str, List[Permission]] = {}
        self.actor_roles: Dict[str, List[str]] = {}
        self.roles: Dict[str, Role] = {}
        
        # Temporary permissions
        self.temporary_permissions: Dict[str, List[Tuple[Permission, float]]] = {}
        
        # Rate limiting
        self.rate_limit_policies: Dict[str, RateLimitPolicy] = {}
        self.token_buckets: Dict[str, TokenBucket] = {}
        
        # Audit logger (injected)
        self.audit_logger = None
    
    def set_audit_logger(self, audit_logger) -> None:
        """Set audit logger.
        
        Args:
            audit_logger: AuditLogger instance
        """
        self.audit_logger = audit_logger
    
    def add_role(self, role: Role) -> None:
        """Add a role definition.
        
        Args:
            role: Role to add
        """
        self.roles[role.name] = role
    
    def assign_role(self, actor: str, role_name: str) -> None:
        """Assign role to actor.
        
        Args:
            actor: Actor identifier
            role_name: Role to assign
            
        Raises:
            KeyError: If role not found
        """
        if role_name not in self.roles:
            raise KeyError(f"Role {role_name} not found")
        
        if actor not in self.actor_roles:
            self.actor_roles[actor] = []
        
        if role_name not in self.actor_roles[actor]:
            self.actor_roles[actor].append(role_name)
    
    def grant_permission(self, actor: str, permission: Permission) -> None:
        """Grant direct permission to actor.
        
        Args:
            actor: Actor identifier
            permission: Permission to grant
        """
        if actor not in self.actor_permissions:
            self.actor_permissions[actor] = []
        
        self.actor_permissions[actor].append(permission)
    
    def grant_temporary_permission(
        self,
        actor: str,
        permission: Permission,
        expires_at: float
    ) -> None:
        """Grant time-limited permission to actor.
        
        Implements Requirement 13.5:
        - Supports temporary permission grants with expiration
        
        Args:
            actor: Actor identifier
            permission: Permission to grant
            expires_at: Unix timestamp when permission expires
        """
        if actor not in self.temporary_permissions:
            self.temporary_permissions[actor] = []
        
        self.temporary_permissions[actor].append((permission, expires_at))
    
    def get_actor_permissions(self, actor: str) -> List[Permission]:
        """Return all permissions for actor (direct + inherited from roles).
        
        Implements Requirement 13.4:
        - Supports permission inheritance through roles
        
        Args:
            actor: Actor identifier
            
        Returns:
            List of all permissions (no duplicates)
        """
        permissions: Set[str] = set()
        result: List[Permission] = []
        
        # Add direct permissions
        if actor in self.actor_permissions:
            for perm in self.actor_permissions[actor]:
                perm_key = f"{perm.name}:{perm.resource_pattern}"
                if perm_key not in permissions:
                    permissions.add(perm_key)
                    result.append(perm)
        
        # Add role-based permissions
        if actor in self.actor_roles:
            for role_name in self.actor_roles[actor]:
                if role_name in self.roles:
                    for perm in self.roles[role_name].permissions:
                        perm_key = f"{perm.name}:{perm.resource_pattern}"
                        if perm_key not in permissions:
                            permissions.add(perm_key)
                            result.append(perm)
        
        # Add valid temporary permissions
        now = time.time()
        if actor in self.temporary_permissions:
            valid_temp = []
            for perm, expires_at in self.temporary_permissions[actor]:
                if now < expires_at:
                    perm_key = f"{perm.name}:{perm.resource_pattern}"
                    if perm_key not in permissions:
                        permissions.add(perm_key)
                        result.append(perm)
                    valid_temp.append((perm, expires_at))
            # Clean up expired permissions
            self.temporary_permissions[actor] = valid_temp
        
        return result
    
    def check_permission(
        self,
        actor: str,
        action: str,
        resource: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Verify actor has permission for action on resource.
        
        Implements Requirements 13.1, 13.2, 13.3, 13.6:
        - Supports endpoint and resource-level permissions
        - Verifies actor has required permission
        - Logs permission denials
        
        Args:
            actor: Actor identifier
            action: Action to perform
            resource: Optional resource identifier
            
        Returns:
            Tuple of (allowed, reason)
        """
        permissions = self.get_actor_permissions(actor)
        
        for perm in permissions:
            # Check action match
            if perm.name == action or perm.name == "*":
                # Check resource match
                if resource is None or perm.resource_pattern is None:
                    return True, "Allowed"
                
                # Wildcard resource
                if perm.resource_pattern == "*":
                    return True, "Allowed"
                
                # Exact resource match
                if perm.resource_pattern == resource:
                    return True, "Allowed"
                
                # Pattern match (simple prefix matching)
                if perm.resource_pattern.endswith("*"):
                    prefix = perm.resource_pattern[:-1]
                    if resource.startswith(prefix):
                        return True, "Allowed"
        
        # Permission denied - log it
        if self.audit_logger:
            self.audit_logger.log_event(
                category="authorization",
                title="Permission denied",
                actor=actor,
                details={
                    "action": action,
                    "resource": resource
                }
            )
        
        return False, f"Permission denied: {action} on {resource}"
    
    def add_rate_limit_policy(self, policy: RateLimitPolicy) -> None:
        """Add rate limiting policy.
        
        Args:
            policy: Rate limit policy
        """
        self.rate_limit_policies[policy.endpoint_pattern] = policy
    
    def _get_token_bucket(
        self,
        client_id: str,
        endpoint: str,
        policy: RateLimitPolicy,
        limit: int
    ) -> TokenBucket:
        """Get or create token bucket for client and endpoint.
        
        Args:
            client_id: Client identifier
            endpoint: Endpoint pattern
            policy: Rate limit policy
            limit: Actual request limit (after role override)
            
        Returns:
            TokenBucket instance
        """
        bucket_key = f"{client_id}:{endpoint}"
        
        if bucket_key not in self.token_buckets:
            # Create new bucket with the actual limit (after role override)
            refill_rate = limit / policy.window_seconds
            self.token_buckets[bucket_key] = TokenBucket(
                capacity=limit,
                tokens=limit,
                last_refill=time.time(),
                refill_rate=refill_rate
            )
        
        return self.token_buckets[bucket_key]
    
    def _refill_bucket(self, bucket: TokenBucket) -> None:
        """Refill token bucket based on elapsed time.
        
        Args:
            bucket: TokenBucket to refill
        """
        now = time.time()
        elapsed = now - bucket.last_refill
        
        # Add tokens based on elapsed time
        tokens_to_add = elapsed * bucket.refill_rate
        bucket.tokens = min(bucket.capacity, bucket.tokens + tokens_to_add)
        bucket.last_refill = now
    
    def check_rate_limit(
        self,
        client_id: str,
        endpoint: str,
        actor_roles: Optional[List[str]] = None
    ) -> Tuple[bool, float]:
        """Check if client is within rate limit using token bucket algorithm.
        
        Implements Requirements 14.1, 14.2, 14.3, 14.4, 14.5, 14.6:
        - Enforces configurable request limits per client per time window
        - Uses token bucket algorithm
        - Supports different limits for different endpoints and roles
        - Resets counters after time window
        - Logs rate limit violations
        
        Args:
            client_id: Client identifier
            endpoint: API endpoint
            actor_roles: Optional list of actor's roles for role-specific limits
            
        Returns:
            Tuple of (allowed, retry_after)
            - allowed: True if within limit, False if exceeded
            - retry_after: Seconds to wait before retry (0 if allowed)
        """
        # Find matching policy
        policy = None
        for pattern, pol in self.rate_limit_policies.items():
            if self._endpoint_matches(endpoint, pattern):
                policy = pol
                break
        
        if policy is None:
            # No policy = no limit
            return True, 0.0
        
        # Check for role-specific override
        limit = policy.requests_per_window
        if actor_roles:
            for role in actor_roles:
                if role in policy.role_overrides:
                    limit = policy.role_overrides[role]
                    break
        
        # Get token bucket with the correct limit (after role override)
        bucket = self._get_token_bucket(client_id, policy.endpoint_pattern, policy, limit)
        
        # Refill bucket
        self._refill_bucket(bucket)
        
        # Check if tokens available
        if bucket.tokens >= 1.0:
            # Consume token
            bucket.tokens -= 1.0
            return True, 0.0
        else:
            # Rate limit exceeded
            retry_after = (1.0 - bucket.tokens) / bucket.refill_rate
            
            # Log violation
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="rate_limit",
                    title="Rate limit exceeded",
                    actor=client_id,
                    details={
                        "endpoint": endpoint,
                        "retry_after": retry_after
                    }
                )
            
            return False, retry_after
    
    def _endpoint_matches(self, endpoint: str, pattern: str) -> bool:
        """Check if endpoint matches pattern.
        
        Args:
            endpoint: Actual endpoint
            pattern: Pattern with wildcards
            
        Returns:
            True if matches
        """
        if pattern == "*":
            return True
        
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return endpoint.startswith(prefix)
        
        return endpoint == pattern


# Predefined roles
ADMIN_ROLE = Role(
    name="admin",
    permissions=[
        Permission(name="*", resource_pattern="*")
    ]
)

OPERATOR_ROLE = Role(
    name="operator",
    permissions=[
        Permission(name="robot:control", resource_pattern="*"),
        Permission(name="task:create", resource_pattern="*"),
        Permission(name="task:read", resource_pattern="*"),
        Permission(name="audit:read", resource_pattern="*"),
    ]
)

ROBOT_ROLE = Role(
    name="robot",
    permissions=[
        Permission(name="task:read", resource_pattern="*"),
        Permission(name="telemetry:write", resource_pattern="*"),
    ]
)
