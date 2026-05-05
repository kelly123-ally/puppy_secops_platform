"""
Security Dashboard API for PuppySecOps Platform

Provides real-time security metrics and alerts via WebSocket streaming.

This module implements the backend API for the security dashboard, enabling:
- Real-time security metrics streaming via WebSocket
- Real-time security alerts streaming via WebSocket
- Historical metrics retrieval for time range analysis
- Tracking of key security indicators

Validates Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from fastapi import WebSocket

if TYPE_CHECKING:
    from app.core.alert_system import AlertSystem
    from app.core.audit_logger import AuditLogger
    from app.core.certificate_manager import CertificateManager
    from app.core.key_manager import KeyManager
    from app.core.anomaly_detector import AnomalyDetector
    from app.core.access_controller import AccessController


@dataclass
class SecurityMetrics:
    """Security metrics snapshot at a point in time.
    
    Attributes:
        timestamp: Unix timestamp when metrics were captured
        blocked_attacks_by_type: Count of blocked attacks grouped by type
        active_robots: Number of active robots in the fleet
        revoked_certificates: Number of revoked certificates
        anomaly_detections: Number of anomaly detections
        authentication_failures: Number of authentication failures
        key_rotation_status: Status of key rotation (last rotation time, next rotation time)
    """
    timestamp: float
    blocked_attacks_by_type: Dict[str, int] = field(default_factory=dict)
    active_robots: int = 0
    revoked_certificates: int = 0
    anomaly_detections: int = 0
    authentication_failures: int = 0
    key_rotation_status: Dict[str, Any] = field(default_factory=dict)


class SecurityDashboardAPI:
    """
    Backend API for security dashboard with real-time metrics and alerts.
    
    Provides WebSocket-based streaming of security metrics and alerts,
    as well as historical metrics retrieval for trend analysis.
    
    Validates Requirements:
    - 19.1: Display security metrics (blocked attacks, active robots, revoked certs, anomalies, auth failures)
    - 19.2: Update metrics in real-time via WebSocket
    - 19.3: Display historical trends for configurable time periods
    - 19.4: Display current alert feed with severity indicators
    - 19.5: Support filtering by time range, robot_id, and event category
    - 19.6: Display key rotation status
    """
    
    def __init__(
        self,
        alert_system: Optional[AlertSystem] = None,
        audit_logger: Optional[AuditLogger] = None,
        certificate_manager: Optional[CertificateManager] = None,
        key_manager: Optional[KeyManager] = None,
        anomaly_detector: Optional[AnomalyDetector] = None,
        access_controller: Optional[AccessController] = None
    ):
        """Initialize Security Dashboard API.
        
        Args:
            alert_system: Alert system for streaming alerts
            audit_logger: Audit logger for retrieving historical events
            certificate_manager: Certificate manager for certificate metrics
            key_manager: Key manager for key rotation status
            anomaly_detector: Anomaly detector for anomaly metrics
            access_controller: Access controller for rate limit metrics
        """
        self.alert_system = alert_system
        self.audit_logger = audit_logger
        self.certificate_manager = certificate_manager
        self.key_manager = key_manager
        self.anomaly_detector = anomaly_detector
        self.access_controller = access_controller
        
        # Connected WebSocket clients for metrics streaming
        self.metrics_clients: Set[WebSocket] = set()
        self.metrics_clients_lock = asyncio.Lock()
        
        # Metrics history storage
        self.metrics_history: List[SecurityMetrics] = []
        self.max_history_size = 10000  # Keep last 10,000 metric snapshots
        
        # Metrics collection interval (seconds)
        self.metrics_interval = 5.0  # Collect metrics every 5 seconds
        
        # Background task for metrics collection
        self._metrics_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def stream_metrics(self, websocket: WebSocket) -> None:
        """Stream real-time security metrics to dashboard via WebSocket.
        
        Implements Requirements 19.1, 19.2, 19.6:
        - Streams security metrics in real-time
        - Updates via WebSocket connection
        - Includes key rotation status
        
        Args:
            websocket: WebSocket connection to dashboard client
        """
        # Accept WebSocket connection
        await websocket.accept()
        
        # Add client to metrics streaming list
        async with self.metrics_clients_lock:
            self.metrics_clients.add(websocket)
        
        try:
            # Send initial metrics snapshot
            current_metrics = self._collect_current_metrics()
            await websocket.send_json({
                "type": "metrics",
                "timestamp": current_metrics.timestamp,
                "blocked_attacks_by_type": current_metrics.blocked_attacks_by_type,
                "active_robots": current_metrics.active_robots,
                "revoked_certificates": current_metrics.revoked_certificates,
                "anomaly_detections": current_metrics.anomaly_detections,
                "authentication_failures": current_metrics.authentication_failures,
                "key_rotation_status": current_metrics.key_rotation_status
            })
            
            # Keep connection alive and wait for disconnect
            while True:
                # Wait for client messages (ping/pong or disconnect)
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                except asyncio.TimeoutError:
                    # Send ping to keep connection alive
                    await websocket.send_json({"type": "ping"})
        
        except Exception:
            # Client disconnected or error occurred
            pass
        
        finally:
            # Remove client from streaming list
            async with self.metrics_clients_lock:
                self.metrics_clients.discard(websocket)
    
    async def stream_alerts(self, websocket: WebSocket) -> None:
        """Stream real-time security alerts to dashboard via WebSocket.
        
        Implements Requirement 19.4:
        - Streams security alerts in real-time
        - Includes severity indicators
        
        Args:
            websocket: WebSocket connection to dashboard client
        """
        if not self.alert_system:
            await websocket.close(code=1011, reason="Alert system not available")
            return
        
        # Use alert system's existing WebSocket streaming
        await self.alert_system.connect_client(websocket)
        
        try:
            # Send recent alert history
            recent_alerts = self.alert_system.get_alert_history(limit=50)
            for alert in recent_alerts:
                await websocket.send_json({
                    "type": "alert",
                    "alert_id": alert.alert_id,
                    "timestamp": alert.timestamp,
                    "severity": alert.severity,
                    "category": alert.category,
                    "subject": alert.subject,
                    "title": alert.title,
                    "details": alert.details
                })
            
            # Keep connection alive
            while True:
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "ping"})
        
        except Exception:
            pass
        
        finally:
            await self.alert_system.disconnect_client(websocket)
    
    def get_metrics_history(
        self,
        start_time: float,
        end_time: float
    ) -> Dict[str, List[float]]:
        """Return historical security metrics for time range.
        
        Implements Requirements 19.3, 19.5:
        - Returns historical metrics for specified time range
        - Supports filtering by time range
        
        Args:
            start_time: Start of time range (Unix timestamp)
            end_time: End of time range (Unix timestamp)
            
        Returns:
            Dictionary mapping metric names to time series data:
            {
                "timestamps": [t1, t2, ...],
                "blocked_attacks": [count1, count2, ...],
                "active_robots": [count1, count2, ...],
                "revoked_certificates": [count1, count2, ...],
                "anomaly_detections": [count1, count2, ...],
                "authentication_failures": [count1, count2, ...]
            }
        """
        # Filter metrics by time range
        filtered_metrics = [
            m for m in self.metrics_history
            if start_time <= m.timestamp <= end_time
        ]
        
        # Build time series data
        timestamps = [m.timestamp for m in filtered_metrics]
        
        # Aggregate blocked attacks across all types
        blocked_attacks = [
            sum(m.blocked_attacks_by_type.values())
            for m in filtered_metrics
        ]
        
        active_robots = [m.active_robots for m in filtered_metrics]
        revoked_certificates = [m.revoked_certificates for m in filtered_metrics]
        anomaly_detections = [m.anomaly_detections for m in filtered_metrics]
        authentication_failures = [m.authentication_failures for m in filtered_metrics]
        
        return {
            "timestamps": timestamps,
            "blocked_attacks": blocked_attacks,
            "active_robots": active_robots,
            "revoked_certificates": revoked_certificates,
            "anomaly_detections": anomaly_detections,
            "authentication_failures": authentication_failures
        }
    
    def get_metrics_history_by_attack_type(
        self,
        start_time: float,
        end_time: float
    ) -> Dict[str, List[float]]:
        """Return historical blocked attacks grouped by type.
        
        Implements Requirement 19.1:
        - Returns blocked attacks by type for trend analysis
        
        Args:
            start_time: Start of time range (Unix timestamp)
            end_time: End of time range (Unix timestamp)
            
        Returns:
            Dictionary mapping attack types to time series:
            {
                "timestamps": [t1, t2, ...],
                "sql_injection": [count1, count2, ...],
                "xss": [count1, count2, ...],
                ...
            }
        """
        # Filter metrics by time range
        filtered_metrics = [
            m for m in self.metrics_history
            if start_time <= m.timestamp <= end_time
        ]
        
        if not filtered_metrics:
            return {"timestamps": []}
        
        # Collect all attack types
        attack_types = set()
        for m in filtered_metrics:
            attack_types.update(m.blocked_attacks_by_type.keys())
        
        # Build time series for each attack type
        result = {"timestamps": [m.timestamp for m in filtered_metrics]}
        
        for attack_type in attack_types:
            result[attack_type] = [
                m.blocked_attacks_by_type.get(attack_type, 0)
                for m in filtered_metrics
            ]
        
        return result
    
    def _collect_current_metrics(self) -> SecurityMetrics:
        """Collect current security metrics from all components.
        
        Returns:
            SecurityMetrics snapshot
        """
        metrics = SecurityMetrics(timestamp=time.time())
        
        # Collect blocked attacks by type from audit logger
        if self.audit_logger:
            # Count blocked attacks from audit events
            # Check both "security" and "threat_blocked" categories
            security_events = []
            seen_event_ids = set()  # Track seen events to avoid duplicates
            
            for category in ["security", "threat_blocked"]:
                try:
                    events = self.audit_logger.get_events_by_category(category)
                    for event in events:
                        # Use event_id to deduplicate if available
                        event_id = getattr(event, 'event_id', id(event))
                        if event_id not in seen_event_ids:
                            security_events.append(event)
                            seen_event_ids.add(event_id)
                except:
                    pass
            
            attack_types: Dict[str, int] = {}
            
            # Keywords that indicate a blocked attack
            blocked_keywords = ["blocked", "rejected", "failed", "invalid"]
            
            for event in security_events:
                title = event.title.lower()
                details = event.details if hasattr(event, 'details') else {}
                
                # Check if this is a blocked attack event
                if any(keyword in title for keyword in blocked_keywords):
                    # Try to get attack type from details first
                    if isinstance(details, dict) and "attack_type" in details:
                        attack_type = details["attack_type"]
                    # Otherwise map event titles to attack types
                    elif "sql" in title or "injection" in title:
                        attack_type = "sql_injection"
                    elif "xss" in title or "script" in title:
                        attack_type = "xss"
                    elif "command" in title:
                        attack_type = "command_injection"
                    elif "replay" in title:
                        attack_type = "replay"
                    elif "spoof" in title or "heartbeat" in title:
                        attack_type = "spoof"
                    elif "completion" in title or "lease" in title:
                        attack_type = "invalid_completion"
                    elif "revoked" in title:
                        attack_type = "revoked_sender"
                    else:
                        attack_type = "other"
                    
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            metrics.blocked_attacks_by_type = attack_types
        
        # Count active robots from key manager
        if self.key_manager:
            active_count = sum(
                1 for key_pair in self.key_manager.robot_keys.values()
                if not key_pair.revoked
            )
            metrics.active_robots = active_count
        
        # Count revoked certificates from certificate manager
        if self.certificate_manager:
            metrics.revoked_certificates = len(self.certificate_manager.crl)
        
        # Count anomaly detections from audit logger
        if self.audit_logger:
            anomaly_events = self.audit_logger.get_events_by_category("anomaly_alert")
            metrics.anomaly_detections = len(anomaly_events)
        
        # Count authentication failures from audit logger
        if self.audit_logger:
            auth_events = self.audit_logger.get_events_by_category("authentication")
            auth_failures = sum(
                1 for event in auth_events
                if not event.details.get("success", True)
            )
            metrics.authentication_failures = auth_failures
        
        # Get key rotation status from key manager
        if self.key_manager:
            # Find most recent and next rotation times
            session_keys = list(self.key_manager.session_keys.values())
            if session_keys:
                most_recent_rotation = max(k.created_at for k in session_keys)
                next_rotation = min(k.expires_at for k in session_keys)
                
                metrics.key_rotation_status = {
                    "last_rotation": most_recent_rotation,
                    "next_rotation": next_rotation,
                    "active_sessions": len(session_keys)
                }
            else:
                metrics.key_rotation_status = {
                    "last_rotation": None,
                    "next_rotation": None,
                    "active_sessions": 0
                }
        
        return metrics
    
    async def _metrics_collection_loop(self) -> None:
        """Background task that periodically collects and broadcasts metrics."""
        while self._running:
            try:
                # Collect current metrics
                current_metrics = self._collect_current_metrics()
                
                # Add to history
                self.metrics_history.append(current_metrics)
                if len(self.metrics_history) > self.max_history_size:
                    self.metrics_history.pop(0)
                
                # Broadcast to connected clients
                await self._broadcast_metrics(current_metrics)
                
                # Wait for next collection interval
                await asyncio.sleep(self.metrics_interval)
            
            except Exception as e:
                # Log error but continue running
                if self.audit_logger:
                    self.audit_logger.log_event(
                        category="dashboard_error",
                        title="Metrics collection error",
                        actor="system",
                        details={"error": str(e)}
                    )
                await asyncio.sleep(self.metrics_interval)
    
    async def _broadcast_metrics(self, metrics: SecurityMetrics) -> None:
        """Broadcast metrics to all connected WebSocket clients.
        
        Args:
            metrics: Metrics to broadcast
        """
        payload = {
            "type": "metrics",
            "timestamp": metrics.timestamp,
            "blocked_attacks_by_type": metrics.blocked_attacks_by_type,
            "active_robots": metrics.active_robots,
            "revoked_certificates": metrics.revoked_certificates,
            "anomaly_detections": metrics.anomaly_detections,
            "authentication_failures": metrics.authentication_failures,
            "key_rotation_status": metrics.key_rotation_status
        }
        
        # Send to all connected clients
        stale_clients = []
        async with self.metrics_clients_lock:
            clients = list(self.metrics_clients)
        
        for client in clients:
            try:
                await client.send_json(payload)
            except Exception:
                # Client disconnected or error sending
                stale_clients.append(client)
        
        # Remove stale clients
        if stale_clients:
            async with self.metrics_clients_lock:
                for client in stale_clients:
                    self.metrics_clients.discard(client)
    
    async def start_metrics_collection(self) -> None:
        """Start background metrics collection task.
        
        Should be called when the application starts.
        """
        if self._running:
            return  # Already running
        
        self._running = True
        self._metrics_task = asyncio.create_task(self._metrics_collection_loop())
    
    async def stop_metrics_collection(self) -> None:
        """Stop background metrics collection task.
        
        Should be called when the application shuts down.
        """
        self._running = False
        
        if self._metrics_task:
            self._metrics_task.cancel()
            try:
                await self._metrics_task
            except asyncio.CancelledError:
                pass
            self._metrics_task = None
    
    def get_current_metrics(self) -> SecurityMetrics:
        """Get current security metrics snapshot.
        
        Returns:
            Current SecurityMetrics
        """
        return self._collect_current_metrics()
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of current security posture.
        
        Returns:
            Dictionary with summary statistics
        """
        current = self._collect_current_metrics()
        
        return {
            "timestamp": current.timestamp,
            "total_blocked_attacks": sum(current.blocked_attacks_by_type.values()),
            "blocked_attacks_by_type": current.blocked_attacks_by_type,
            "active_robots": current.active_robots,
            "revoked_certificates": current.revoked_certificates,
            "anomaly_detections": current.anomaly_detections,
            "authentication_failures": current.authentication_failures,
            "key_rotation_status": current.key_rotation_status
        }
