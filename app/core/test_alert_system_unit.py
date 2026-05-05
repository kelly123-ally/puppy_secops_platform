"""
Unit tests for AlertSystem

Tests alert generation, WebSocket delivery, severity levels,
configurable rules, and audit logging integration.

Requirements: 12.1-12.6
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import WebSocket

from app.core.alert_system import (
    ANOMALY_ALERTS_RULE,
    AUTH_FAILURE_RULE,
    CRITICAL_EVENTS_RULE,
    HIGH_SEVERITY_RULE,
    Alert,
    AlertRule,
    AlertSystem,
)
from app.core.audit_logger import AuditLogger


@pytest.fixture
def audit_logger():
    """Create audit logger for testing."""
    return AuditLogger(
        signing_key_path="test_alert_signing_key.pem",
        genesis_hash_path="test_alert_genesis.txt",
        storage_path="test_alert_events.json"
    )


@pytest.fixture
def alert_system(audit_logger):
    """Create alert system for testing."""
    return AlertSystem(audit_logger=audit_logger)


@pytest.fixture
def mock_websocket():
    """Create mock WebSocket for testing."""
    ws = AsyncMock(spec=WebSocket)
    ws.send_json = AsyncMock()
    return ws


class TestAlertGeneration:
    """Test alert generation functionality."""
    
    @pytest.mark.asyncio
    async def test_generate_alert_with_valid_severity(self, alert_system):
        """Test generating alert with valid severity level."""
        alert_id = await alert_system.generate_alert(
            severity="critical",
            category="cert_revocation",
            subject="dog1",
            title="Certificate revoked",
            details={"reason": "compromised"}
        )
        
        assert alert_id != ""
        assert alert_id.startswith("alert_")
        assert alert_system.get_alert_count() == 1
    
    @pytest.mark.asyncio
    async def test_generate_alert_with_invalid_severity(self, alert_system):
        """Test that invalid severity raises ValueError."""
        with pytest.raises(ValueError, match="Invalid severity"):
            await alert_system.generate_alert(
                severity="invalid",
                category="test",
                subject="test",
                title="Test alert"
            )
    
    @pytest.mark.asyncio
    async def test_generate_alert_all_severity_levels(self, alert_system):
        """Test generating alerts with all severity levels (Requirement 12.3)."""
        severities = ["low", "medium", "high", "critical"]
        
        for severity in severities:
            alert_id = await alert_system.generate_alert(
                severity=severity,
                category="test",
                subject="test",
                title=f"Test {severity} alert"
            )
            assert alert_id != ""
        
        assert alert_system.get_alert_count() == 4
    
    @pytest.mark.asyncio
    async def test_alert_generation_timing(self, alert_system):
        """Test that alerts are generated within 1 second (Requirement 12.1)."""
        start_time = time.time()
        
        await alert_system.generate_alert(
            severity="critical",
            category="cert_revocation",
            subject="dog1",
            title="Certificate revoked"
        )
        
        elapsed = time.time() - start_time
        
        # Alert generation should be nearly instantaneous (< 1 second)
        assert elapsed < 1.0, f"Alert generation took {elapsed:.3f}s, expected < 1s"
    
    @pytest.mark.asyncio
    async def test_alert_includes_timestamp(self, alert_system):
        """Test that generated alerts include timestamp."""
        before = time.time()
        
        await alert_system.generate_alert(
            severity="high",
            category="auth_failure",
            subject="user1",
            title="Authentication failed"
        )
        
        after = time.time()
        
        alerts = alert_system.get_alert_history()
        assert len(alerts) == 1
        assert before <= alerts[0].timestamp <= after
    
    @pytest.mark.asyncio
    async def test_alert_includes_details(self, alert_system):
        """Test that alert details are preserved."""
        details = {
            "ip_address": "192.168.1.100",
            "attempt_count": 5,
            "reason": "invalid_password"
        }
        
        await alert_system.generate_alert(
            severity="high",
            category="auth_failure",
            subject="user1",
            title="Repeated authentication failures",
            details=details
        )
        
        alerts = alert_system.get_alert_history()
        assert alerts[0].details == details


class TestWebSocketDelivery:
    """Test WebSocket-based alert delivery."""
    
    @pytest.mark.asyncio
    async def test_connect_client(self, alert_system, mock_websocket):
        """Test connecting a WebSocket client."""
        await alert_system.connect_client(mock_websocket)
        
        assert mock_websocket in alert_system.clients
        mock_websocket.accept.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_client(self, alert_system, mock_websocket):
        """Test disconnecting a WebSocket client."""
        await alert_system.connect_client(mock_websocket)
        await alert_system.disconnect_client(mock_websocket)
        
        assert mock_websocket not in alert_system.clients
    
    @pytest.mark.asyncio
    async def test_alert_delivered_to_connected_clients(self, alert_system, mock_websocket):
        """Test that alerts are delivered via WebSocket (Requirement 12.2)."""
        await alert_system.connect_client(mock_websocket)
        
        await alert_system.generate_alert(
            severity="critical",
            category="cert_revocation",
            subject="dog1",
            title="Certificate revoked"
        )
        
        # Give async task time to complete
        await asyncio.sleep(0.1)
        
        # Verify WebSocket received the alert
        mock_websocket.send_json.assert_called_once()
        call_args = mock_websocket.send_json.call_args[0][0]
        
        assert call_args["type"] == "alert"
        assert call_args["severity"] == "critical"
        assert call_args["category"] == "cert_revocation"
        assert call_args["subject"] == "dog1"
        assert call_args["title"] == "Certificate revoked"
    
    @pytest.mark.asyncio
    async def test_alert_delivered_to_multiple_clients(self, alert_system):
        """Test that alerts are delivered to all connected clients."""
        clients = [AsyncMock(spec=WebSocket) for _ in range(3)]
        
        for client in clients:
            client.send_json = AsyncMock()
            await alert_system.connect_client(client)
        
        await alert_system.generate_alert(
            severity="high",
            category="anomaly",
            subject="dog2",
            title="Anomaly detected"
        )
        
        # Give async task time to complete
        await asyncio.sleep(0.1)
        
        # Verify all clients received the alert
        for client in clients:
            client.send_json.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_stale_clients_removed_on_error(self, alert_system):
        """Test that clients with send errors are removed."""
        good_client = AsyncMock(spec=WebSocket)
        good_client.send_json = AsyncMock()
        
        bad_client = AsyncMock(spec=WebSocket)
        bad_client.send_json = AsyncMock(side_effect=Exception("Connection closed"))
        
        await alert_system.connect_client(good_client)
        await alert_system.connect_client(bad_client)
        
        await alert_system.generate_alert(
            severity="medium",
            category="test",
            subject="test",
            title="Test alert"
        )
        
        # Give async task time to complete
        await asyncio.sleep(0.1)
        
        # Bad client should be removed
        assert good_client in alert_system.clients
        assert bad_client not in alert_system.clients


class TestAlertRules:
    """Test configurable alert rules."""
    
    @pytest.mark.asyncio
    async def test_add_alert_rule(self, alert_system):
        """Test adding alert rule (Requirement 12.5)."""
        rule = AlertRule(
            rule_id="test_rule",
            category="test",
            severity_threshold="high",
            enabled=True,
            description="Test rule"
        )
        
        alert_system.add_alert_rule(rule)
        
        assert rule in alert_system.rules
    
    @pytest.mark.asyncio
    async def test_alert_suppressed_by_severity_threshold(self, alert_system):
        """Test that alerts below threshold are suppressed."""
        rule = AlertRule(
            rule_id="high_only",
            category="*",
            severity_threshold="high",
            enabled=True
        )
        alert_system.add_alert_rule(rule)
        
        # Low severity should be suppressed
        alert_id = await alert_system.generate_alert(
            severity="low",
            category="test",
            subject="test",
            title="Low severity alert"
        )
        
        assert alert_id == ""  # Suppressed
        assert alert_system.get_alert_count() == 0
    
    @pytest.mark.asyncio
    async def test_alert_generated_above_threshold(self, alert_system):
        """Test that alerts at or above threshold are generated."""
        rule = AlertRule(
            rule_id="medium_and_above",
            category="*",
            severity_threshold="medium",
            enabled=True
        )
        alert_system.add_alert_rule(rule)
        
        # High severity should be generated
        alert_id = await alert_system.generate_alert(
            severity="high",
            category="test",
            subject="test",
            title="High severity alert"
        )
        
        assert alert_id != ""
        assert alert_system.get_alert_count() == 1
    
    @pytest.mark.asyncio
    async def test_alert_rule_category_filtering(self, alert_system):
        """Test alert rules filter by category."""
        rule = AlertRule(
            rule_id="anomaly_only",
            category="anomaly",
            severity_threshold="low",
            enabled=True
        )
        alert_system.add_alert_rule(rule)
        
        # Anomaly category should be generated
        alert_id1 = await alert_system.generate_alert(
            severity="low",
            category="anomaly",
            subject="dog1",
            title="Anomaly detected"
        )
        
        # Other category should be suppressed
        alert_id2 = await alert_system.generate_alert(
            severity="low",
            category="auth_failure",
            subject="user1",
            title="Auth failed"
        )
        
        assert alert_id1 != ""
        assert alert_id2 == ""
        assert alert_system.get_alert_count() == 1
    
    @pytest.mark.asyncio
    async def test_wildcard_category_matches_all(self, alert_system):
        """Test that wildcard category matches all events."""
        rule = AlertRule(
            rule_id="all_critical",
            category="*",
            severity_threshold="critical",
            enabled=True
        )
        alert_system.add_alert_rule(rule)
        
        categories = ["cert_revocation", "auth_failure", "anomaly", "key_rotation_failure"]
        
        for category in categories:
            alert_id = await alert_system.generate_alert(
                severity="critical",
                category=category,
                subject="test",
                title=f"Critical {category}"
            )
            assert alert_id != ""
        
        assert alert_system.get_alert_count() == 4
    
    @pytest.mark.asyncio
    async def test_disabled_rule_does_not_apply(self, alert_system):
        """Test that disabled rules do not affect alert generation."""
        rule = AlertRule(
            rule_id="disabled_rule",
            category="*",
            severity_threshold="critical",
            enabled=False  # Disabled
        )
        alert_system.add_alert_rule(rule)
        
        # With only disabled rule, no alerts should be generated
        alert_id = await alert_system.generate_alert(
            severity="low",
            category="test",
            subject="test",
            title="Test alert"
        )
        
        # No rules enabled, so alert should not be generated
        assert alert_id == ""
    
    def test_remove_alert_rule(self, alert_system):
        """Test removing alert rule."""
        rule = AlertRule(
            rule_id="test_rule",
            category="test",
            severity_threshold="high"
        )
        alert_system.add_alert_rule(rule)
        
        removed = alert_system.remove_alert_rule("test_rule")
        
        assert removed is True
        assert rule not in alert_system.rules
    
    def test_remove_nonexistent_rule(self, alert_system):
        """Test removing nonexistent rule returns False."""
        removed = alert_system.remove_alert_rule("nonexistent")
        
        assert removed is False
    
    def test_update_alert_rule(self, alert_system):
        """Test updating alert rule."""
        rule = AlertRule(
            rule_id="test_rule",
            category="test",
            severity_threshold="high",
            enabled=True
        )
        alert_system.add_alert_rule(rule)
        
        updated = alert_system.update_alert_rule("test_rule", enabled=False)
        
        assert updated is True
        assert rule.enabled is False


class TestAuditLogging:
    """Test audit logging integration."""
    
    @pytest.mark.asyncio
    async def test_alert_logged_to_audit_logger(self, alert_system, audit_logger):
        """Test that alerts are logged to audit logger (Requirement 12.4)."""
        initial_count = audit_logger.get_event_count()
        
        await alert_system.generate_alert(
            severity="critical",
            category="cert_revocation",
            subject="dog1",
            title="Certificate revoked",
            details={"reason": "compromised"}
        )
        
        # Verify audit event was created
        assert audit_logger.get_event_count() == initial_count + 1
        
        # Verify audit event details
        events = audit_logger.get_events_by_category("security_alert")
        assert len(events) > 0
        
        latest_event = events[-1]
        assert latest_event.title == "Alert generated: Certificate revoked"
        assert latest_event.actor == "alert_system"
        assert latest_event.details["severity"] == "critical"
        assert latest_event.details["alert_category"] == "cert_revocation"
        assert latest_event.details["subject"] == "dog1"
    
    @pytest.mark.asyncio
    async def test_alert_rule_addition_logged(self, alert_system, audit_logger):
        """Test that alert rule additions are logged."""
        initial_count = audit_logger.get_event_count()
        
        rule = AlertRule(
            rule_id="test_rule",
            category="test",
            severity_threshold="high",
            description="Test rule"
        )
        alert_system.add_alert_rule(rule)
        
        assert audit_logger.get_event_count() == initial_count + 1
        
        events = audit_logger.get_events_by_category("alert_configuration")
        assert len(events) > 0
        assert events[-1].title == "Alert rule added"


class TestAlertHistory:
    """Test alert history management."""
    
    @pytest.mark.asyncio
    async def test_get_alert_history(self, alert_system):
        """Test retrieving alert history."""
        await alert_system.generate_alert(
            severity="high",
            category="test1",
            subject="test",
            title="Alert 1"
        )
        await alert_system.generate_alert(
            severity="medium",
            category="test2",
            subject="test",
            title="Alert 2"
        )
        
        history = alert_system.get_alert_history()
        
        assert len(history) == 2
        assert history[0].title == "Alert 1"
        assert history[1].title == "Alert 2"
    
    @pytest.mark.asyncio
    async def test_filter_history_by_severity(self, alert_system):
        """Test filtering alert history by severity."""
        await alert_system.generate_alert(
            severity="critical",
            category="test",
            subject="test",
            title="Critical alert"
        )
        await alert_system.generate_alert(
            severity="low",
            category="test",
            subject="test",
            title="Low alert"
        )
        
        critical_alerts = alert_system.get_alert_history(severity="critical")
        
        assert len(critical_alerts) == 1
        assert critical_alerts[0].severity == "critical"
    
    @pytest.mark.asyncio
    async def test_filter_history_by_category(self, alert_system):
        """Test filtering alert history by category."""
        await alert_system.generate_alert(
            severity="high",
            category="anomaly",
            subject="dog1",
            title="Anomaly alert"
        )
        await alert_system.generate_alert(
            severity="high",
            category="auth_failure",
            subject="user1",
            title="Auth alert"
        )
        
        anomaly_alerts = alert_system.get_alert_history(category="anomaly")
        
        assert len(anomaly_alerts) == 1
        assert anomaly_alerts[0].category == "anomaly"
    
    @pytest.mark.asyncio
    async def test_filter_history_by_time_range(self, alert_system):
        """Test filtering alert history by time range."""
        start_time = time.time()
        
        await alert_system.generate_alert(
            severity="high",
            category="test",
            subject="test",
            title="Alert 1"
        )
        
        await asyncio.sleep(0.1)
        mid_time = time.time()
        
        await alert_system.generate_alert(
            severity="high",
            category="test",
            subject="test",
            title="Alert 2"
        )
        
        # Get alerts after mid_time
        recent_alerts = alert_system.get_alert_history(start_time=mid_time)
        
        assert len(recent_alerts) == 1
        assert recent_alerts[0].title == "Alert 2"
    
    @pytest.mark.asyncio
    async def test_history_limit(self, alert_system):
        """Test limiting number of returned alerts."""
        for i in range(10):
            await alert_system.generate_alert(
                severity="low",
                category="test",
                subject="test",
                title=f"Alert {i}"
            )
        
        limited = alert_system.get_alert_history(limit=5)
        
        assert len(limited) == 5
        # Should return last 5 alerts
        assert limited[-1].title == "Alert 9"
    
    @pytest.mark.asyncio
    async def test_history_max_size(self, alert_system):
        """Test that history is limited to max size."""
        alert_system.max_history_size = 10
        
        # Generate more alerts than max size
        for i in range(15):
            await alert_system.generate_alert(
                severity="low",
                category="test",
                subject="test",
                title=f"Alert {i}"
            )
        
        # History should be limited to max size
        assert alert_system.get_alert_count() == 10
    
    def test_get_alert_count_by_severity(self, alert_system):
        """Test getting alert counts by severity."""
        asyncio.run(alert_system.generate_alert("critical", "test", "test", "Alert 1"))
        asyncio.run(alert_system.generate_alert("critical", "test", "test", "Alert 2"))
        asyncio.run(alert_system.generate_alert("high", "test", "test", "Alert 3"))
        asyncio.run(alert_system.generate_alert("low", "test", "test", "Alert 4"))
        
        counts = alert_system.get_alert_count_by_severity()
        
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 0
        assert counts["low"] == 1
    
    def test_get_alert_count_by_category(self, alert_system):
        """Test getting alert counts by category."""
        asyncio.run(alert_system.generate_alert("high", "anomaly", "test", "Alert 1"))
        asyncio.run(alert_system.generate_alert("high", "anomaly", "test", "Alert 2"))
        asyncio.run(alert_system.generate_alert("high", "auth_failure", "test", "Alert 3"))
        
        counts = alert_system.get_alert_count_by_category()
        
        assert counts["anomaly"] == 2
        assert counts["auth_failure"] == 1
    
    def test_clear_alert_history(self, alert_system):
        """Test clearing alert history."""
        asyncio.run(alert_system.generate_alert("high", "test", "test", "Alert 1"))
        asyncio.run(alert_system.generate_alert("high", "test", "test", "Alert 2"))
        
        alert_system.clear_alert_history()
        
        assert alert_system.get_alert_count() == 0


class TestCriticalEvents:
    """Test critical event definitions."""
    
    def test_critical_event_categories_defined(self):
        """Test that critical event categories are defined (Requirement 12.6)."""
        expected_categories = {
            "cert_revocation",
            "auth_failure_repeated",
            "anomaly_critical",
            "key_rotation_failure"
        }
        
        assert AlertSystem.CRITICAL_EVENTS == expected_categories


class TestPredefinedRules:
    """Test predefined alert rules."""
    
    def test_critical_events_rule(self):
        """Test predefined critical events rule."""
        assert CRITICAL_EVENTS_RULE.rule_id == "critical_events"
        assert CRITICAL_EVENTS_RULE.category == "*"
        assert CRITICAL_EVENTS_RULE.severity_threshold == "critical"
        assert CRITICAL_EVENTS_RULE.enabled is True
    
    def test_high_severity_rule(self):
        """Test predefined high severity rule."""
        assert HIGH_SEVERITY_RULE.rule_id == "high_severity"
        assert HIGH_SEVERITY_RULE.severity_threshold == "high"
    
    def test_anomaly_alerts_rule(self):
        """Test predefined anomaly alerts rule."""
        assert ANOMALY_ALERTS_RULE.rule_id == "anomaly_alerts"
        assert ANOMALY_ALERTS_RULE.category == "anomaly"
        assert ANOMALY_ALERTS_RULE.severity_threshold == "medium"
    
    def test_auth_failure_rule(self):
        """Test predefined auth failure rule."""
        assert AUTH_FAILURE_RULE.rule_id == "auth_failures"
        assert AUTH_FAILURE_RULE.category == "auth_failure"
        assert AUTH_FAILURE_RULE.severity_threshold == "high"
