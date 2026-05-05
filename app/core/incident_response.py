"""
Incident Response Engine for PuppySecOps Platform

Provides automated incident response including:
- Configurable response rules mapping alert types to actions
- Automated certificate revocation for critical anomalies
- Temporary client blocking for repeated authentication failures
- Rate limit extension for repeated violations
- Manual override support for automated actions

Requirements: 18.1-18.6
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from app.core.access_controller import AccessController
from app.core.audit_logger import AuditLogger
from app.core.certificate_manager import CertificateManager


@dataclass
class SecurityAlert:
    """Security alert requiring incident response.
    
    Attributes:
        alert_id: Unique alert identifier
        timestamp: Unix timestamp when alert occurred
        severity: Alert severity (critical, high, medium, low)
        category: Alert category (anomaly, auth_failure, rate_limit_violation)
        subject: Subject of alert (robot_id or user)
        details: Additional alert-specific information
    """
    alert_id: str
    timestamp: float
    severity: str
    category: str
    subject: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseRule:
    """Incident response rule mapping alerts to actions.
    
    Attributes:
        alert_category: Alert category to match
        severity_threshold: Minimum severity to trigger (critical, high, medium, low)
        actions: List of actions to execute (revoke_cert, block_client, extend_rate_limit)
        auto_execute: Whether to execute automatically or require manual approval
    """
    alert_category: str
    severity_threshold: str
    actions: List[str]
    auto_execute: bool = True


class IncidentResponseEngine:
    """Automated incident response engine for threat containment.
    
    Processes security alerts and executes configured automated responses
    including certificate revocation, client blocking, and rate limit extension.
    """
    
    # Severity levels (higher number = more severe)
    SEVERITY_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    
    def __init__(
        self,
        cert_manager: CertificateManager,
        access_controller: AccessController,
        audit_logger: AuditLogger
    ):
        """Initialize Incident Response Engine.
        
        Args:
            cert_manager: Certificate manager for certificate revocation
            access_controller: Access controller for client blocking and rate limiting
            audit_logger: Audit logger for logging all actions
        """
        self.cert_manager = cert_manager
        self.access_controller = access_controller
        self.audit_logger = audit_logger
        
        # Response rules
        self.response_rules: List[ResponseRule] = []
        
        # Blocked clients (client_id -> unblock_time)
        self.blocked_clients: Dict[str, float] = {}
        
        # Manual overrides (action_id -> override_reason)
        self.overrides: Dict[str, str] = {}
        
        # Action execution history (for tracking)
        self.action_history: List[Dict[str, Any]] = []
    
    def add_response_rule(self, rule: ResponseRule) -> None:
        """Add incident response rule.
        
        Implements Requirement 18.1:
        - Supports configurable incident response rules
        
        Args:
            rule: Response rule to add
        """
        self.response_rules.append(rule)
        
        self.audit_logger.log_event(
            category="incident_response",
            title="Response rule added",
            actor="system",
            details={
                "alert_category": rule.alert_category,
                "severity_threshold": rule.severity_threshold,
                "actions": rule.actions,
                "auto_execute": rule.auto_execute
            }
        )
    
    def handle_alert(self, alert: SecurityAlert) -> List[str]:
        """Process security alert and execute configured responses.
        
        Implements Requirements 18.1, 18.2, 18.3, 18.4, 18.5:
        - Processes security alerts
        - Executes configured automated actions
        - Logs all actions to audit logger
        
        Args:
            alert: Security alert to process
            
        Returns:
            List of action IDs that were executed
        """
        executed_actions = []
        
        # Find matching rules
        matching_rules = self._find_matching_rules(alert)
        
        if not matching_rules:
            # No matching rules, just log the alert
            self.audit_logger.log_event(
                category="incident_response",
                title="Alert received (no matching rules)",
                actor="system",
                details={
                    "alert_id": alert.alert_id,
                    "severity": alert.severity,
                    "category": alert.category,
                    "subject": alert.subject,
                    "alert_details": alert.details
                }
            )
            return executed_actions
        
        # Execute actions for each matching rule
        for rule in matching_rules:
            if not rule.auto_execute:
                # Log that manual approval is required
                self.audit_logger.log_event(
                    category="incident_response",
                    title="Alert requires manual approval",
                    actor="system",
                    details={
                        "alert_id": alert.alert_id,
                        "severity": alert.severity,
                        "category": alert.category,
                        "subject": alert.subject,
                        "rule_actions": rule.actions
                    }
                )
                continue
            
            # Execute each action in the rule
            for action in rule.actions:
                action_id = self._execute_action(alert, action)
                if action_id:
                    executed_actions.append(action_id)
        
        return executed_actions
    
    def _find_matching_rules(self, alert: SecurityAlert) -> List[ResponseRule]:
        """Find response rules matching the alert.
        
        Args:
            alert: Security alert
            
        Returns:
            List of matching response rules
        """
        matching = []
        
        for rule in self.response_rules:
            # Check category match
            if rule.alert_category != alert.category and rule.alert_category != "*":
                continue
            
            # Check severity threshold
            alert_severity_level = self.SEVERITY_LEVELS.get(alert.severity, 0)
            threshold_level = self.SEVERITY_LEVELS.get(rule.severity_threshold, 0)
            
            if alert_severity_level >= threshold_level:
                matching.append(rule)
        
        return matching
    
    def _execute_action(self, alert: SecurityAlert, action: str) -> Optional[str]:
        """Execute a specific action in response to an alert.
        
        Args:
            alert: Security alert
            action: Action to execute
            
        Returns:
            Action ID if executed, None if skipped
        """
        action_id = f"{alert.alert_id}_{action}_{int(time.time())}"
        
        # Check for manual override
        if action_id in self.overrides:
            self.audit_logger.log_event(
                category="incident_response",
                title="Action overridden",
                actor="system",
                details={
                    "action_id": action_id,
                    "alert_id": alert.alert_id,
                    "action": action,
                    "override_reason": self.overrides[action_id]
                }
            )
            return None
        
        # Execute the action
        try:
            if action == "revoke_cert":
                self._revoke_certificate(alert, action_id)
            elif action == "block_client":
                self._block_client(alert, action_id)
            elif action == "extend_rate_limit":
                self._extend_rate_limit(alert, action_id)
            else:
                # Unknown action
                self.audit_logger.log_event(
                    category="incident_response",
                    title="Unknown action",
                    actor="system",
                    details={
                        "action_id": action_id,
                        "alert_id": alert.alert_id,
                        "action": action
                    }
                )
                return None
            
            # Record action in history
            self.action_history.append({
                "action_id": action_id,
                "alert_id": alert.alert_id,
                "action": action,
                "subject": alert.subject,
                "timestamp": time.time()
            })
            
            return action_id
            
        except Exception as e:
            # Log action failure
            self.audit_logger.log_event(
                category="incident_response",
                title="Action execution failed",
                actor="system",
                details={
                    "action_id": action_id,
                    "alert_id": alert.alert_id,
                    "action": action,
                    "error": str(e)
                }
            )
            return None
    
    def _revoke_certificate(self, alert: SecurityAlert, action_id: str) -> None:
        """Revoke certificate for subject in alert.
        
        Implements Requirement 18.2:
        - Automatically revokes robot certificate for critical anomalies
        
        Args:
            alert: Security alert
            action_id: Action identifier
        """
        robot_id = alert.subject
        reason = f"Automated revocation: {alert.category} - {alert.severity}"
        
        # Revoke certificate
        self.cert_manager.revoke_certificate(robot_id, reason)
        
        # Log action
        self.audit_logger.log_event(
            category="incident_response",
            title="Certificate revoked (automated)",
            actor="system",
            details={
                "action_id": action_id,
                "alert_id": alert.alert_id,
                "robot_id": robot_id,
                "reason": reason,
                "alert_severity": alert.severity,
                "alert_category": alert.category
            }
        )
    
    def _block_client(self, alert: SecurityAlert, action_id: str) -> None:
        """Temporarily block client.
        
        Implements Requirement 18.3:
        - Temporarily blocks client for repeated authentication failures
        
        Args:
            alert: Security alert
            action_id: Action identifier
        """
        client_id = alert.subject
        
        # Determine block duration based on severity and history
        block_duration = self._calculate_block_duration(client_id, alert.severity)
        unblock_time = time.time() + block_duration
        
        # Block client
        self.blocked_clients[client_id] = unblock_time
        
        # Log action
        self.audit_logger.log_event(
            category="incident_response",
            title="Client blocked (automated)",
            actor="system",
            details={
                "action_id": action_id,
                "alert_id": alert.alert_id,
                "client_id": client_id,
                "block_duration_seconds": block_duration,
                "unblock_time": unblock_time,
                "alert_severity": alert.severity,
                "alert_category": alert.category
            }
        )
    
    def _extend_rate_limit(self, alert: SecurityAlert, action_id: str) -> None:
        """Extend rate limit block duration for repeated violations.
        
        Implements Requirement 18.4:
        - Extends block duration for repeated rate limit violations
        
        Args:
            alert: Security alert
            action_id: Action identifier
        """
        client_id = alert.subject
        
        # Calculate extended block duration
        current_block = self.blocked_clients.get(client_id, time.time())
        extension_duration = self._calculate_extension_duration(client_id, alert.severity)
        
        # Extend block
        new_unblock_time = max(current_block, time.time()) + extension_duration
        self.blocked_clients[client_id] = new_unblock_time
        
        # Log action
        self.audit_logger.log_event(
            category="incident_response",
            title="Rate limit extended (automated)",
            actor="system",
            details={
                "action_id": action_id,
                "alert_id": alert.alert_id,
                "client_id": client_id,
                "extension_duration_seconds": extension_duration,
                "new_unblock_time": new_unblock_time,
                "alert_severity": alert.severity,
                "alert_category": alert.category
            }
        )
    
    def _calculate_block_duration(self, client_id: str, severity: str) -> float:
        """Calculate block duration based on severity and history.
        
        Args:
            client_id: Client identifier
            severity: Alert severity
            
        Returns:
            Block duration in seconds
        """
        # Base durations by severity
        base_durations = {
            "low": 60,        # 1 minute
            "medium": 300,    # 5 minutes
            "high": 900,      # 15 minutes
            "critical": 3600  # 1 hour
        }
        
        base_duration = base_durations.get(severity, 300)
        
        # Count previous blocks for this client
        previous_blocks = sum(
            1 for action in self.action_history
            if action["subject"] == client_id and action["action"] == "block_client"
        )
        
        # Exponential backoff for repeat offenders
        multiplier = 2 ** min(previous_blocks, 5)  # Cap at 32x
        
        return base_duration * multiplier
    
    def _calculate_extension_duration(self, client_id: str, severity: str) -> float:
        """Calculate rate limit extension duration.
        
        Args:
            client_id: Client identifier
            severity: Alert severity
            
        Returns:
            Extension duration in seconds
        """
        # Base extensions by severity
        base_extensions = {
            "low": 120,       # 2 minutes
            "medium": 600,    # 10 minutes
            "high": 1800,     # 30 minutes
            "critical": 7200  # 2 hours
        }
        
        base_extension = base_extensions.get(severity, 600)
        
        # Count previous extensions for this client
        previous_extensions = sum(
            1 for action in self.action_history
            if action["subject"] == client_id and action["action"] == "extend_rate_limit"
        )
        
        # Exponential backoff for repeat offenders
        multiplier = 2 ** min(previous_extensions, 4)  # Cap at 16x
        
        return base_extension * multiplier
    
    def override_action(self, action_id: str, reason: str) -> None:
        """Manually override an automated action.
        
        Implements Requirement 18.6:
        - Supports manual override of automated actions
        
        Args:
            action_id: Action identifier to override
            reason: Reason for override
        """
        self.overrides[action_id] = reason
        
        self.audit_logger.log_event(
            category="incident_response",
            title="Action manually overridden",
            actor="admin",
            details={
                "action_id": action_id,
                "reason": reason
            }
        )
    
    def is_client_blocked(self, client_id: str) -> bool:
        """Check if client is currently blocked.
        
        Args:
            client_id: Client identifier
            
        Returns:
            True if blocked, False otherwise
        """
        if client_id not in self.blocked_clients:
            return False
        
        unblock_time = self.blocked_clients[client_id]
        now = time.time()
        
        if now >= unblock_time:
            # Block expired, remove it
            del self.blocked_clients[client_id]
            return False
        
        return True
    
    def unblock_client(self, client_id: str, reason: str) -> None:
        """Manually unblock a client.
        
        Args:
            client_id: Client identifier
            reason: Reason for unblocking
        """
        if client_id in self.blocked_clients:
            del self.blocked_clients[client_id]
            
            self.audit_logger.log_event(
                category="incident_response",
                title="Client manually unblocked",
                actor="admin",
                details={
                    "client_id": client_id,
                    "reason": reason
                }
            )
    
    def get_blocked_clients(self) -> Dict[str, float]:
        """Get all currently blocked clients.
        
        Returns:
            Dictionary of client_id -> unblock_time
        """
        # Clean up expired blocks
        now = time.time()
        expired = [
            client_id for client_id, unblock_time in self.blocked_clients.items()
            if now >= unblock_time
        ]
        for client_id in expired:
            del self.blocked_clients[client_id]
        
        return self.blocked_clients.copy()
    
    def get_action_history(
        self,
        subject: Optional[str] = None,
        action: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get action execution history.
        
        Args:
            subject: Optional filter by subject
            action: Optional filter by action type
            
        Returns:
            List of action records
        """
        history = self.action_history
        
        if subject:
            history = [h for h in history if h["subject"] == subject]
        
        if action:
            history = [h for h in history if h["action"] == action]
        
        return history


# Predefined response rules for common scenarios
CRITICAL_ANOMALY_RULE = ResponseRule(
    alert_category="anomaly",
    severity_threshold="critical",
    actions=["revoke_cert"],
    auto_execute=True
)

REPEATED_AUTH_FAILURE_RULE = ResponseRule(
    alert_category="auth_failure",
    severity_threshold="high",
    actions=["block_client"],
    auto_execute=True
)

RATE_LIMIT_VIOLATION_RULE = ResponseRule(
    alert_category="rate_limit_violation",
    severity_threshold="medium",
    actions=["extend_rate_limit"],
    auto_execute=True
)
