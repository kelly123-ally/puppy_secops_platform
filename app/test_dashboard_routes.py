"""
Unit tests for Security Dashboard API routes.

Tests the dashboard API endpoints added to app/routes.py for Task 18.2.

Validates Requirements: 19.4, 19.5, 19.6
"""

import time

import pytest
from fastapi.testclient import TestClient

from app.main import app


class TestDashboardRoutes:
    """Test suite for Security Dashboard API routes."""
    
    def test_dashboard_api_initialized(self):
        """Test that SecurityDashboardAPI is initialized during app startup."""
        with TestClient(app) as client:
            # Verify dashboard_api is in app state
            assert hasattr(app.state, 'dashboard_api')
            assert app.state.dashboard_api is not None
    
    def test_metrics_summary_endpoint_requires_auth(self):
        """Test that metrics summary endpoint requires authentication."""
        with TestClient(app) as client:
            # Attempt to access without authentication
            response = client.get("/api/dashboard/metrics/summary")
            
            # Should return 401 Unauthorized
            assert response.status_code == 401
    
    def test_metrics_summary_endpoint_with_auth(self):
        """Test metrics summary endpoint with valid authentication."""
        with TestClient(app) as client:
            # Login as admin
            login_response = client.post(
                "/api/login",
                json={"username": "admin", "password": "Admin123!"}
            )
            assert login_response.status_code == 200
            
            # Get metrics summary
            response = client.get("/api/dashboard/metrics/summary")
            
            # Should return 200 OK
            assert response.status_code == 200
            
            # Verify response structure
            data = response.json()
            assert "timestamp" in data
            assert "total_blocked_attacks" in data
            assert "blocked_attacks_by_type" in data
            assert "active_robots" in data
            assert "revoked_certificates" in data
            assert "anomaly_detections" in data
            assert "authentication_failures" in data
            assert "key_rotation_status" in data
    
    def test_metrics_history_endpoint_requires_auth(self):
        """Test that metrics history endpoint requires authentication."""
        with TestClient(app) as client:
            # Attempt to access without authentication
            response = client.get("/api/dashboard/metrics/history")
            
            # Should return 401 Unauthorized
            assert response.status_code == 401
    
    def test_metrics_history_endpoint_with_auth(self):
        """Test metrics history endpoint with valid authentication."""
        with TestClient(app) as client:
            # Login as admin
            login_response = client.post(
                "/api/login",
                json={"username": "admin", "password": "Admin123!"}
            )
            assert login_response.status_code == 200
            
            # Get metrics history with time range
            now = time.time()
            start_time = now - 3600  # 1 hour ago
            response = client.get(
                f"/api/dashboard/metrics/history?start_time={start_time}&end_time={now}"
            )
            
            # Should return 200 OK
            assert response.status_code == 200
            
            # Verify response structure
            data = response.json()
            assert "start_time" in data
            assert "end_time" in data
            assert "metrics" in data
            
            metrics = data["metrics"]
            assert "timestamps" in metrics
            assert "blocked_attacks" in metrics
            assert "active_robots" in metrics
            assert "revoked_certificates" in metrics
            assert "anomaly_detections" in metrics
            assert "authentication_failures" in metrics
    
    def test_metrics_by_attack_type_endpoint_requires_auth(self):
        """Test that attack type breakdown endpoint requires authentication."""
        with TestClient(app) as client:
            # Attempt to access without authentication
            response = client.get("/api/dashboard/metrics/history/by-attack-type")
            
            # Should return 401 Unauthorized
            assert response.status_code == 401
    
    def test_metrics_by_attack_type_endpoint_with_auth(self):
        """Test attack type breakdown endpoint with valid authentication."""
        with TestClient(app) as client:
            # Login as admin
            login_response = client.post(
                "/api/login",
                json={"username": "admin", "password": "Admin123!"}
            )
            assert login_response.status_code == 200
            
            # Get attack type breakdown with time range
            now = time.time()
            start_time = now - 3600  # 1 hour ago
            response = client.get(
                f"/api/dashboard/metrics/history/by-attack-type?start_time={start_time}&end_time={now}"
            )
            
            # Should return 200 OK
            assert response.status_code == 200
            
            # Verify response structure
            data = response.json()
            assert "start_time" in data
            assert "end_time" in data
            assert "attack_types" in data
            
            attack_types = data["attack_types"]
            assert "timestamps" in attack_types
    
    def test_metrics_history_default_time_range(self):
        """Test that metrics history uses default time range when not specified."""
        with TestClient(app) as client:
            # Login as admin
            login_response = client.post(
                "/api/login",
                json={"username": "admin", "password": "Admin123!"}
            )
            assert login_response.status_code == 200
            
            # Get metrics history without time range parameters
            response = client.get("/api/dashboard/metrics/history")
            
            # Should return 200 OK
            assert response.status_code == 200
            
            # Verify response has time range
            data = response.json()
            assert data["start_time"] == 0  # Default start time
            assert data["end_time"] > 0  # Should be current time
    
    def test_operator_can_access_dashboard_endpoints(self):
        """Test that operator role can access dashboard endpoints."""
        with TestClient(app) as client:
            # Login as operator
            login_response = client.post(
                "/api/login",
                json={"username": "operator", "password": "Operator123!"}
            )
            assert login_response.status_code == 200
            
            # Operator should be able to access metrics summary
            response = client.get("/api/dashboard/metrics/summary")
            assert response.status_code == 200
            
            # Operator should be able to access metrics history
            response = client.get("/api/dashboard/metrics/history")
            assert response.status_code == 200
            
            # Operator should be able to access attack type breakdown
            response = client.get("/api/dashboard/metrics/history/by-attack-type")
            assert response.status_code == 200
    
    def test_auditor_can_access_dashboard_endpoints(self):
        """Test that auditor role can access dashboard endpoints."""
        with TestClient(app) as client:
            # Login as auditor
            login_response = client.post(
                "/api/login",
                json={"username": "auditor", "password": "Auditor123!"}
            )
            assert login_response.status_code == 200
            
            # Auditor should be able to access metrics summary
            response = client.get("/api/dashboard/metrics/summary")
            assert response.status_code == 200
            
            # Auditor should be able to access metrics history
            response = client.get("/api/dashboard/metrics/history")
            assert response.status_code == 200
            
            # Auditor should be able to access attack type breakdown
            response = client.get("/api/dashboard/metrics/history/by-attack-type")
            assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
