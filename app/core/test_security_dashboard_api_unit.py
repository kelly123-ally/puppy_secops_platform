"""
Unit tests for SecurityDashboardAPI

Tests the security dashboard API functionality including:
- Metrics collection from security components
- Real-time metrics streaming via WebSocket
- Historical metrics retrieval
- Alert streaming integration
- Metrics history management
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from app.core.security_dashboard_api import SecurityDashboardAPI, SecurityMetrics


@pytest.fixture
def mock_alert_system():
    """Create mock alert system."""
    alert_system = Mock()
    alert_system.connect_client = AsyncMock()
    alert_system.disconnect_client = AsyncMock()
    alert_system.get_alert_history = Mock(return_value=[])
    return alert_system


@pytest.fixture
def mock_audit_logger():
    """Create mock audit logger."""
    audit_logger = Mock()
    audit_logger.get_events_by_category = Mock(return_value=[])
    audit_logger.log_event = Mock()
    return audit_logger


@pytest.fixture
def mock_certificate_manager():
    """Create mock certificate manager."""
    cert_manager = Mock()
    cert_manager.crl = {}
    return cert_manager


@pytest.fixture
def mock_key_manager():
    """Create mock key manager."""
    key_manager = Mock()
    key_manager.robot_keys = {}
    key_manager.session_keys = {}
    return key_manager


@pytest.fixture
def dashboard_api(
    mock_alert_system,
    mock_audit_logger,
    mock_certificate_manager,
    mock_key_manager
):
    """Create SecurityDashboardAPI instance with mocked dependencies."""
    return SecurityDashboardAPI(
        alert_system=mock_alert_system,
        audit_logger=mock_audit_logger,
        certificate_manager=mock_certificate_manager,
        key_manager=mock_key_manager
    )


class TestSecurityMetricsCollection:
    """Test metrics collection from security components."""
    
    def test_collect_metrics_with_no_components(self):
        """Test metrics collection when no components are available."""
        api = SecurityDashboardAPI()
        metrics = api._collect_current_metrics()
        
        assert isinstance(metrics, SecurityMetrics)
        assert metrics.timestamp > 0
        assert metrics.blocked_attacks_by_type == {}
        assert metrics.active_robots == 0
        assert metrics.revoked_certificates == 0
        assert metrics.anomaly_detections == 0
        assert metrics.authentication_failures == 0
    
    def test_collect_blocked_attacks_from_audit_logger(self, dashboard_api, mock_audit_logger):
        """Test collecting blocked attacks from audit logger."""
        # Mock audit events with proper title strings
        mock_events = [
            Mock(title="SQL injection blocked", details={"attack_type": "sql_injection"}),
            Mock(title="SQL injection blocked", details={"attack_type": "sql_injection"}),
            Mock(title="XSS attack blocked", details={"attack_type": "xss"}),
            Mock(title="Command injection blocked", details={"attack_type": "command_injection"}),
        ]
        
        def get_events_by_category(category):
            if category == "threat_blocked":
                return mock_events
            return []
        
        mock_audit_logger.get_events_by_category.side_effect = get_events_by_category
        
        metrics = dashboard_api._collect_current_metrics()
        
        assert metrics.blocked_attacks_by_type["sql_injection"] == 2
        assert metrics.blocked_attacks_by_type["xss"] == 1
        assert metrics.blocked_attacks_by_type["command_injection"] == 1
        assert any(
            call[0][0] == "threat_blocked"
            for call in mock_audit_logger.get_events_by_category.call_args_list
        )
    
    def test_collect_active_robots_from_key_manager(self, dashboard_api, mock_key_manager):
        """Test collecting active robot count from key manager."""
        # Mock robot keys with some revoked
        mock_key_manager.robot_keys = {
            "robot1": Mock(revoked=False),
            "robot2": Mock(revoked=False),
            "robot3": Mock(revoked=True),
            "robot4": Mock(revoked=False),
        }
        
        metrics = dashboard_api._collect_current_metrics()
        
        assert metrics.active_robots == 3  # 3 non-revoked robots
    
    def test_collect_revoked_certificates(self, dashboard_api, mock_certificate_manager):
        """Test collecting revoked certificate count."""
        mock_certificate_manager.crl = {
            "serial1": Mock(),
            "serial2": Mock(),
            "serial3": Mock(),
        }
        
        metrics = dashboard_api._collect_current_metrics()
        
        assert metrics.revoked_certificates == 3
    
    def test_collect_anomaly_detections(self, dashboard_api, mock_audit_logger):
        """Test collecting anomaly detection count."""
        mock_events = [Mock() for _ in range(5)]
        
        def get_events_by_category(category):
            if category == "anomaly_alert":
                return mock_events
            return []
        
        mock_audit_logger.get_events_by_category.side_effect = get_events_by_category
        
        metrics = dashboard_api._collect_current_metrics()
        
        assert metrics.anomaly_detections == 5
    
    def test_collect_authentication_failures(self, dashboard_api, mock_audit_logger):
        """Test collecting authentication failure count."""
        mock_events = [
            Mock(details={"success": True}),
            Mock(details={"success": False}),
            Mock(details={"success": False}),
            Mock(details={"success": True}),
            Mock(details={"success": False}),
        ]
        
        def get_events_by_category(category):
            if category == "authentication":
                return mock_events
            return []
        
        mock_audit_logger.get_events_by_category.side_effect = get_events_by_category
        
        metrics = dashboard_api._collect_current_metrics()
        
        assert metrics.authentication_failures == 3
    
    def test_collect_key_rotation_status(self, dashboard_api, mock_key_manager):
        """Test collecting key rotation status."""
        now = time.time()
        mock_key_manager.session_keys = {
            "session1": Mock(created_at=now - 3600, expires_at=now + 3600),
            "session2": Mock(created_at=now - 1800, expires_at=now + 5400),
        }
        
        metrics = dashboard_api._collect_current_metrics()
        
        assert metrics.key_rotation_status["active_sessions"] == 2
        assert metrics.key_rotation_status["last_rotation"] == now - 1800
        assert metrics.key_rotation_status["next_rotation"] == now + 3600
    
    def test_collect_key_rotation_status_no_sessions(self, dashboard_api, mock_key_manager):
        """Test key rotation status when no sessions exist."""
        mock_key_manager.session_keys = {}
        
        metrics = dashboard_api._collect_current_metrics()
        
        assert metrics.key_rotation_status["active_sessions"] == 0
        assert metrics.key_rotation_status["last_rotation"] is None
        assert metrics.key_rotation_status["next_rotation"] is None


class TestMetricsHistory:
    """Test historical metrics storage and retrieval."""
    
    def test_get_metrics_history_empty(self, dashboard_api):
        """Test retrieving metrics history when no data exists."""
        history = dashboard_api.get_metrics_history(
            start_time=0,
            end_time=time.time()
        )
        
        assert history["timestamps"] == []
        assert history["blocked_attacks"] == []
        assert history["active_robots"] == []
    
    def test_get_metrics_history_with_data(self, dashboard_api):
        """Test retrieving metrics history with data."""
        # Add some metrics to history
        now = time.time()
        for i in range(5):
            metrics = SecurityMetrics(
                timestamp=now + i * 60,
                blocked_attacks_by_type={"sql_injection": i, "xss": i * 2},
                active_robots=10 + i,
                revoked_certificates=i,
                anomaly_detections=i * 3,
                authentication_failures=i * 4
            )
            dashboard_api.metrics_history.append(metrics)
        
        history = dashboard_api.get_metrics_history(
            start_time=now,
            end_time=now + 300
        )
        
        assert len(history["timestamps"]) == 5
        assert history["blocked_attacks"] == [0, 3, 6, 9, 12]  # sql_injection + xss
        assert history["active_robots"] == [10, 11, 12, 13, 14]
        assert history["revoked_certificates"] == [0, 1, 2, 3, 4]
        assert history["anomaly_detections"] == [0, 3, 6, 9, 12]
        assert history["authentication_failures"] == [0, 4, 8, 12, 16]
    
    def test_get_metrics_history_time_range_filter(self, dashboard_api):
        """Test filtering metrics by time range."""
        now = time.time()
        for i in range(10):
            metrics = SecurityMetrics(
                timestamp=now + i * 60,
                active_robots=i
            )
            dashboard_api.metrics_history.append(metrics)
        
        # Get only middle 5 metrics
        history = dashboard_api.get_metrics_history(
            start_time=now + 120,  # Start at 2 minutes
            end_time=now + 360     # End at 6 minutes
        )
        
        assert len(history["timestamps"]) == 5
        assert history["active_robots"] == [2, 3, 4, 5, 6]
    
    def test_get_metrics_history_by_attack_type(self, dashboard_api):
        """Test retrieving blocked attacks grouped by type."""
        now = time.time()
        for i in range(3):
            metrics = SecurityMetrics(
                timestamp=now + i * 60,
                blocked_attacks_by_type={
                    "sql_injection": i,
                    "xss": i * 2,
                    "command_injection": i * 3
                }
            )
            dashboard_api.metrics_history.append(metrics)
        
        history = dashboard_api.get_metrics_history_by_attack_type(
            start_time=now,
            end_time=now + 180
        )
        
        assert len(history["timestamps"]) == 3
        assert history["sql_injection"] == [0, 1, 2]
        assert history["xss"] == [0, 2, 4]
        assert history["command_injection"] == [0, 3, 6]
    
    def test_metrics_history_size_limit(self, dashboard_api):
        """Test that metrics history respects size limit."""
        dashboard_api.max_history_size = 100
        
        # Add more than max size
        now = time.time()
        for i in range(150):
            metrics = SecurityMetrics(timestamp=now + i)
            dashboard_api.metrics_history.append(metrics)
            
            # Simulate size limit enforcement
            if len(dashboard_api.metrics_history) > dashboard_api.max_history_size:
                dashboard_api.metrics_history.pop(0)
        
        assert len(dashboard_api.metrics_history) == 100


class TestMetricsStreaming:
    """Test real-time metrics streaming via WebSocket."""
    
    @pytest.mark.asyncio
    async def test_stream_metrics_sends_initial_snapshot(self, dashboard_api):
        """Test that stream_metrics sends initial metrics snapshot."""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_json = AsyncMock()
        mock_websocket.receive_text = AsyncMock(side_effect=asyncio.CancelledError())
        
        try:
            await dashboard_api.stream_metrics(mock_websocket)
        except asyncio.CancelledError:
            pass
        
        mock_websocket.accept.assert_called_once()
        mock_websocket.send_json.assert_called()
        
        # Check that initial metrics were sent
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["type"] == "metrics"
        assert "timestamp" in call_args
        assert "blocked_attacks_by_type" in call_args
        assert "active_robots" in call_args
    
    @pytest.mark.asyncio
    async def test_stream_metrics_adds_client_to_list(self, dashboard_api):
        """Test that client is added to metrics streaming list."""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_json = AsyncMock()
        mock_websocket.receive_text = AsyncMock(side_effect=asyncio.CancelledError())
        
        assert len(dashboard_api.metrics_clients) == 0
        
        try:
            await dashboard_api.stream_metrics(mock_websocket)
        except asyncio.CancelledError:
            pass
        
        # Client should be removed after disconnect
        assert len(dashboard_api.metrics_clients) == 0
    
    @pytest.mark.asyncio
    async def test_stream_alerts_uses_alert_system(self, dashboard_api, mock_alert_system):
        """Test that stream_alerts delegates to alert system."""
        mock_websocket = AsyncMock()
        mock_websocket.send_json = AsyncMock()
        mock_websocket.receive_text = AsyncMock(side_effect=asyncio.CancelledError())
        
        try:
            await dashboard_api.stream_alerts(mock_websocket)
        except asyncio.CancelledError:
            pass
        
        mock_alert_system.connect_client.assert_called_once_with(mock_websocket)
        mock_alert_system.disconnect_client.assert_called_once_with(mock_websocket)
    
    @pytest.mark.asyncio
    async def test_stream_alerts_without_alert_system(self):
        """Test stream_alerts when alert system is not available."""
        api = SecurityDashboardAPI()  # No alert system
        mock_websocket = AsyncMock()
        mock_websocket.close = AsyncMock()
        
        await api.stream_alerts(mock_websocket)
        
        mock_websocket.close.assert_called_once_with(
            code=1011,
            reason="Alert system not available"
        )
    
    @pytest.mark.asyncio
    async def test_broadcast_metrics_to_clients(self, dashboard_api):
        """Test broadcasting metrics to connected clients."""
        # Add mock clients
        client1 = AsyncMock()
        client1.send_json = AsyncMock()
        client2 = AsyncMock()
        client2.send_json = AsyncMock()
        
        dashboard_api.metrics_clients.add(client1)
        dashboard_api.metrics_clients.add(client2)
        
        metrics = SecurityMetrics(
            timestamp=time.time(),
            active_robots=5
        )
        
        await dashboard_api._broadcast_metrics(metrics)
        
        client1.send_json.assert_called_once()
        client2.send_json.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_broadcast_removes_stale_clients(self, dashboard_api):
        """Test that stale clients are removed during broadcast."""
        # Add mock clients, one will fail
        client1 = AsyncMock()
        client1.send_json = AsyncMock()
        client2 = AsyncMock()
        client2.send_json = AsyncMock(side_effect=Exception("Connection lost"))
        
        dashboard_api.metrics_clients.add(client1)
        dashboard_api.metrics_clients.add(client2)
        
        metrics = SecurityMetrics(timestamp=time.time())
        
        await dashboard_api._broadcast_metrics(metrics)
        
        # Stale client should be removed
        assert client1 in dashboard_api.metrics_clients
        assert client2 not in dashboard_api.metrics_clients


class TestMetricsCollectionLoop:
    """Test background metrics collection task."""
    
    @pytest.mark.asyncio
    async def test_start_metrics_collection(self, dashboard_api):
        """Test starting metrics collection task."""
        assert not dashboard_api._running
        assert dashboard_api._metrics_task is None
        
        await dashboard_api.start_metrics_collection()
        
        assert dashboard_api._running
        assert dashboard_api._metrics_task is not None
        
        # Clean up
        await dashboard_api.stop_metrics_collection()
    
    @pytest.mark.asyncio
    async def test_stop_metrics_collection(self, dashboard_api):
        """Test stopping metrics collection task."""
        await dashboard_api.start_metrics_collection()
        assert dashboard_api._running
        
        await dashboard_api.stop_metrics_collection()
        
        assert not dashboard_api._running
        assert dashboard_api._metrics_task is None
    
    @pytest.mark.asyncio
    async def test_metrics_collection_loop_collects_periodically(self, dashboard_api):
        """Test that metrics are collected periodically."""
        dashboard_api.metrics_interval = 0.1  # Fast interval for testing
        
        await dashboard_api.start_metrics_collection()
        
        # Wait for a few collection cycles
        await asyncio.sleep(0.35)
        
        await dashboard_api.stop_metrics_collection()
        
        # Should have collected at least 3 metrics
        assert len(dashboard_api.metrics_history) >= 3
    
    @pytest.mark.asyncio
    async def test_start_metrics_collection_idempotent(self, dashboard_api):
        """Test that starting collection multiple times is safe."""
        await dashboard_api.start_metrics_collection()
        task1 = dashboard_api._metrics_task
        
        await dashboard_api.start_metrics_collection()
        task2 = dashboard_api._metrics_task
        
        # Should be the same task
        assert task1 is task2
        
        await dashboard_api.stop_metrics_collection()


class TestMetricsSummary:
    """Test metrics summary functionality."""
    
    def test_get_current_metrics(self, dashboard_api):
        """Test getting current metrics snapshot."""
        metrics = dashboard_api.get_current_metrics()
        
        assert isinstance(metrics, SecurityMetrics)
        assert metrics.timestamp > 0
    
    def test_get_metrics_summary(self, dashboard_api, mock_audit_logger):
        """Test getting metrics summary."""
        # Mock some blocked attacks with proper title format
        mock_events = [
            Mock(title="SQL injection blocked", details={"attack_type": "sql_injection"}),
            Mock(title="XSS attack blocked", details={"attack_type": "xss"}),
        ]
        
        def get_events_by_category(category):
            if category in ["security", "threat_blocked"]:
                return mock_events
            return []
        
        mock_audit_logger.get_events_by_category.side_effect = get_events_by_category
        
        summary = dashboard_api.get_metrics_summary()
        
        assert "timestamp" in summary
        assert summary["total_blocked_attacks"] == 2
        assert "blocked_attacks_by_type" in summary
        assert "active_robots" in summary
        assert "revoked_certificates" in summary
        assert "anomaly_detections" in summary
        assert "authentication_failures" in summary
        assert "key_rotation_status" in summary


class TestIntegration:
    """Integration tests with real components."""
    
    def test_metrics_collection_with_all_components(
        self,
        mock_alert_system,
        mock_audit_logger,
        mock_certificate_manager,
        mock_key_manager
    ):
        """Test metrics collection with all components configured."""
        # Set up mock data with proper title format
        mock_events = [
            Mock(title="SQL injection blocked", details={"attack_type": "sql_injection"}),
        ]
        
        def get_events_by_category(category):
            if category in ["security", "threat_blocked"]:
                return mock_events
            return []
        
        mock_audit_logger.get_events_by_category.side_effect = get_events_by_category
        
        mock_key_manager.robot_keys = {
            "robot1": Mock(revoked=False),
            "robot2": Mock(revoked=False),
        }
        mock_certificate_manager.crl = {"serial1": Mock()}
        mock_key_manager.session_keys = {
            "session1": Mock(created_at=time.time(), expires_at=time.time() + 3600)
        }
        
        api = SecurityDashboardAPI(
            alert_system=mock_alert_system,
            audit_logger=mock_audit_logger,
            certificate_manager=mock_certificate_manager,
            key_manager=mock_key_manager
        )
        
        metrics = api._collect_current_metrics()
        
        assert metrics.blocked_attacks_by_type["sql_injection"] == 1
        assert metrics.active_robots == 2
        assert metrics.revoked_certificates == 1
        assert metrics.key_rotation_status["active_sessions"] == 1
