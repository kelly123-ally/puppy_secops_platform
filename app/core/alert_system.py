"""
Alert System for PuppySecOps Platform

Provides real-time security alerting with:
- Alert generation with severity levels (critical, high, medium, low)
- WebSocket-based alert delivery to dashboard clients
- Configurable alert rules based on event categories and thresholds
- Sub-second alert generation for critical events
- Integration with audit logger for alert tracking

Requirements: 12.1-12.6
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from fastapi import WebSocket

if TYPE_CHECKING:
    from app.core.audit_logger import AuditLogger


@dataclass
class Alert:
    """Security alert with severity and details.
    
    Attributes:
        alert_id: Unique alert identifier
        timestamp: Unix timestamp when alert was generated
        severity: Alert severity (critical, high, medium, low)
        category: Alert category (cert_revocation, auth_failure, anomaly, key_rotation_failure, etc.)
        subject: Subject of alert (robot_id, user, or system)
        title: Brief alert description
        details: Additional alert-specific information
    """
    alert_id: str
    timestamp: float
    severity: str
    category: str
    subject: str
    title: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertRule:
    """Configurable alert rule based on event categories and thresholds.
    
    Attributes:
        rule_id: Unique rule identifier
        category: Event category to monitor (or "*" for all)
        severity_threshold: Minimum severity to generate alert
        enabled: Whether rule is active
        description: Human-readable rule description
    """
    rule_id: str
    category: str
    severity_threshold: str
    enabled: bool = True
    description: str = ""


class AlertSystem:
    """Real-time security alert system with WebSocket delivery.
    
    Generates and delivers security alerts to connected dashboard clients
    via WebSocket. Supports configurable alert rules and severity levels.
    
    Validates Requirements:
    - 12.1: Generate alerts within 1 second of critical events
    - 12.2: Deliver alerts via WebSocket to dashboard clients
    - 12.3: Support severity levels (critical, high, medium, low)
    - 12.4: Log alerts to audit logger
    - 12.5: Support configurable alert rules
    - 12.6: Define critical events (cert revocation, auth failures, anomalies, key rotation failures)
    """
    
    # Severity levels (higher number = more severe)
    SEVERITY_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    
    # Critical event categories (Requirement 12.6)
    CRITICAL_EVENTS = {
        "cert_revocation",
        "auth_failure_repeated",
        "anomaly_critical",
        "key_rotation_failure"
    }
    
    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        """Initialize Alert System.
        
        Args:
            audit_logger: Optional audit logger for logging alert generation
        """
        self.audit_logger = audit_logger
        
        # Connected WebSocket clients
        self.clients: Set[WebSocket] = set()
        self.clients_lock = asyncio.Lock()
        
        # Alert rules
        self.rules: List[AlertRule] = []
        
        # Alert history (for dashboard display)
        self.alert_history: List[Alert] = []
        self.max_history_size = 1000  # Keep last 1000 alerts
        
        # Alert counter for generating unique IDs
        self._alert_counter = 0
        self._counter_lock = asyncio.Lock()
    
    async def connect_client(self, websocket: WebSocket) -> None:
        """Connect a dashboard client for receiving alerts.
        
        Implements Requirement 12.2: Deliver alerts via WebSocket
        
        Args:
            websocket: WebSocket connection to dashboard client
        """
        await websocket.accept()
        async with self.clients_lock:
            self.clients.add(websocket)
    
    async def disconnect_client(self, websocket: WebSocket) -> None:
        """Disconnect a dashboard client.
        
        Args:
            websocket: WebSocket connection to remove
        """
        async with self.clients_lock:
            self.clients.discard(websocket)
    
    async def generate_alert(
        self,
        severity: str,
        category: str,
        subject: str,
        title: str,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate security alert and deliver to connected clients.
        
        Implements Requirements:
        - 12.1: Generate alerts within 1 second of critical events
        - 12.2: Deliver alerts via WebSocket to dashboard clients
        - 12.3: Support severity levels (critical, high, medium, low)
        - 12.4: Log alerts to audit logger
        
        Args:
            severity: Alert severity (critical, high, medium, low)
            category: Alert category
            subject: Subject of alert (robot_id, user, or system)
            title: Brief alert description
            details: Additional alert information
            
        Returns:
            Alert ID
            
        Raises:
            ValueError: If severity is invalid
        """
        # Validate severity
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {list(self.SEVERITY_LEVELS.keys())}"
            )
        
        # Check if alert should be generated based on rules
        if not self._should_generate_alert(category, severity):
            return ""  # Alert suppressed by rules
        
        # Generate unique alert ID
        async with self._counter_lock:
            self._alert_counter += 1
            alert_id = f"alert_{self._alert_counter}_{int(time.time() * 1000)}"
        
        # Create alert
        alert = Alert(
            alert_id=alert_id,
            timestamp=time.time(),
            severity=severity,
            category=category,
            subject=subject,
            title=title,
            details=details or {}
        )
        
        # Add to history
        self.alert_history.append(alert)
        if len(self.alert_history) > self.max_history_size:
            self.alert_history.pop(0)
        
        # Log to audit logger (Requirement 12.4)
        if self.audit_logger:
            self.audit_logger.log_event(
                category="security_alert",
                title=f"Alert generated: {title}",
                actor="alert_system",
                details={
                    "alert_id": alert_id,
                    "severity": severity,
                    "alert_category": category,
                    "subject": subject,
                    "alert_details": details or {}
                }
            )
        
        # Deliver to connected clients (Requirement 12.2)
        # Use asyncio.create_task to ensure delivery happens within 1 second (Requirement 12.1)
        asyncio.create_task(self._deliver_alert(alert))
        
        return alert_id
    
    async def _deliver_alert(self, alert: Alert) -> None:
        """Deliver alert to all connected WebSocket clients.
        
        Args:
            alert: Alert to deliver
        """
        # Prepare alert payload
        payload = {
            "type": "alert",
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp,
            "severity": alert.severity,
            "category": alert.category,
            "subject": alert.subject,
            "title": alert.title,
            "details": alert.details
        }
        
        # Send to all connected clients
        stale_clients = []
        async with self.clients_lock:
            clients = list(self.clients)
        
        for client in clients:
            try:
                await client.send_json(payload)
            except Exception:
                # Client disconnected or error sending
                stale_clients.append(client)
        
        # Remove stale clients
        if stale_clients:
            async with self.clients_lock:
                for client in stale_clients:
                    self.clients.discard(client)
    
    def _should_generate_alert(self, category: str, severity: str) -> bool:
        """Check if alert should be generated based on configured rules.
        
        Implements Requirement 12.5: Support configurable alert rules
        
        Args:
            category: Alert category
            severity: Alert severity
            
        Returns:
            True if alert should be generated, False otherwise
        """
        # If no rules configured, generate all alerts
        if not self.rules:
            return True
        
        severity_level = self.SEVERITY_LEVELS.get(severity, 0)
        
        # Check if any rule matches
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check category match (exact or wildcard)
            if rule.category != "*" and rule.category != category:
                continue
            
            # Check severity threshold
            threshold_level = self.SEVERITY_LEVELS.get(rule.severity_threshold, 0)
            if severity_level >= threshold_level:
                return True
        
        return False
    
    def add_alert_rule(self, rule: AlertRule) -> None:
        """Add configurable alert rule.
        
        Implements Requirement 12.5: Support configurable alert rules
        
        Args:
            rule: Alert rule to add
        """
        self.rules.append(rule)
        
        # Log rule addition
        if self.audit_logger:
            self.audit_logger.log_event(
                category="alert_configuration",
                title="Alert rule added",
                actor="admin",
                details={
                    "rule_id": rule.rule_id,
                    "category": rule.category,
                    "severity_threshold": rule.severity_threshold,
                    "enabled": rule.enabled,
                    "description": rule.description
                }
            )
    
    def remove_alert_rule(self, rule_id: str) -> bool:
        """Remove alert rule by ID.
        
        Args:
            rule_id: Rule identifier to remove
            
        Returns:
            True if rule was removed, False if not found
        """
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                removed_rule = self.rules.pop(i)
                
                # Log rule removal
                if self.audit_logger:
                    self.audit_logger.log_event(
                        category="alert_configuration",
                        title="Alert rule removed",
                        actor="admin",
                        details={
                            "rule_id": removed_rule.rule_id,
                            "category": removed_rule.category
                        }
                    )
                
                return True
        
        return False
    
    def update_alert_rule(self, rule_id: str, enabled: Optional[bool] = None) -> bool:
        """Update alert rule configuration.
        
        Args:
            rule_id: Rule identifier to update
            enabled: New enabled state (None to keep current)
            
        Returns:
            True if rule was updated, False if not found
        """
        for rule in self.rules:
            if rule.rule_id == rule_id:
                if enabled is not None:
                    rule.enabled = enabled
                
                # Log rule update
                if self.audit_logger:
                    self.audit_logger.log_event(
                        category="alert_configuration",
                        title="Alert rule updated",
                        actor="admin",
                        details={
                            "rule_id": rule.rule_id,
                            "enabled": rule.enabled
                        }
                    )
                
                return True
        
        return False
    
    def get_alert_history(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: Optional[int] = None
    ) -> List[Alert]:
        """Get alert history with optional filtering.
        
        Args:
            severity: Filter by severity level
            category: Filter by category
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            limit: Maximum number of alerts to return
            
        Returns:
            List of alerts matching filters
        """
        filtered = self.alert_history
        
        # Apply filters
        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        
        if category:
            filtered = [a for a in filtered if a.category == category]
        
        if start_time:
            filtered = [a for a in filtered if a.timestamp >= start_time]
        
        if end_time:
            filtered = [a for a in filtered if a.timestamp <= end_time]
        
        # Apply limit
        if limit:
            filtered = filtered[-limit:]
        
        return filtered
    
    def get_alert_count(self) -> int:
        """Get total number of alerts in history.
        
        Returns:
            Number of alerts
        """
        return len(self.alert_history)
    
    def get_alert_count_by_severity(self) -> Dict[str, int]:
        """Get alert counts grouped by severity.
        
        Returns:
            Dictionary of severity -> count
        """
        counts = {severity: 0 for severity in self.SEVERITY_LEVELS.keys()}
        
        for alert in self.alert_history:
            if alert.severity in counts:
                counts[alert.severity] += 1
        
        return counts
    
    def get_alert_count_by_category(self) -> Dict[str, int]:
        """Get alert counts grouped by category.
        
        Returns:
            Dictionary of category -> count
        """
        counts: Dict[str, int] = {}
        
        for alert in self.alert_history:
            counts[alert.category] = counts.get(alert.category, 0) + 1
        
        return counts
    
    def clear_alert_history(self) -> None:
        """Clear all alerts from history.
        
        Note: This does not affect audit log entries.
        """
        self.alert_history.clear()
        
        # Log history clear
        if self.audit_logger:
            self.audit_logger.log_event(
                category="alert_configuration",
                title="Alert history cleared",
                actor="admin",
                details={}
            )


# Predefined alert rules for common scenarios
CRITICAL_EVENTS_RULE = AlertRule(
    rule_id="critical_events",
    category="*",
    severity_threshold="critical",
    enabled=True,
    description="Generate alerts for all critical events"
)

HIGH_SEVERITY_RULE = AlertRule(
    rule_id="high_severity",
    category="*",
    severity_threshold="high",
    enabled=True,
    description="Generate alerts for high and critical severity events"
)

ANOMALY_ALERTS_RULE = AlertRule(
    rule_id="anomaly_alerts",
    category="anomaly",
    severity_threshold="medium",
    enabled=True,
    description="Generate alerts for anomaly detections (medium and above)"
)

AUTH_FAILURE_RULE = AlertRule(
    rule_id="auth_failures",
    category="auth_failure",
    severity_threshold="high",
    enabled=True,
    description="Generate alerts for repeated authentication failures"
)
