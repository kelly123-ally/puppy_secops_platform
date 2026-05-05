"""
Unit tests for Security Dashboard page route.

Tests the /security-dashboard page route added to app/routes.py for Task 19.2.

Validates Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


class TestSecurityDashboardPage:
    """Test suite for Security Dashboard page route."""
    
    def test_security_dashboard_page_requires_auth(self):
        """Test that security dashboard page requires authentication."""
        with TestClient(app) as client:
            # Attempt to access without authentication
            response = client.get("/security-dashboard", follow_redirects=False)
            
            # Should redirect to login page
            assert response.status_code == 302
            assert response.headers["location"] == "/"
    
    def test_security_dashboard_page_with_auth(self):
        """Test security dashboard page with valid authentication."""
        with TestClient(app) as client:
            # Login as admin
            login_response = client.post(
                "/api/login",
                json={"username": "admin", "password": "Admin123!"}
            )
            assert login_response.status_code == 200
            
            # Access security dashboard page
            response = client.get("/security-dashboard")
            
            # Should return 200 OK
            assert response.status_code == 200
            
            # Verify HTML content
            html = response.text
            assert "Security Dashboard" in html
            assert "Security Monitoring Dashboard" in html
            assert "security_dashboard.css" in html
            assert "security_dashboard.js" in html
            assert "chart.js" in html or "Chart.js" in html
    
    def test_security_dashboard_page_includes_user_context(self):
        """Test that security dashboard page includes user context."""
        with TestClient(app) as client:
            # Login as operator
            login_response = client.post(
                "/api/login",
                json={"username": "operator", "password": "Operator123!"}
            )
            assert login_response.status_code == 200
            
            # Access security dashboard page
            response = client.get("/security-dashboard")
            
            # Should return 200 OK
            assert response.status_code == 200
            
            # Verify user context is included
            html = response.text
            assert "operator" in html.lower()
    
    def test_security_dashboard_page_includes_required_elements(self):
        """Test that security dashboard page includes all required UI elements."""
        with TestClient(app) as client:
            # Login as admin
            login_response = client.post(
                "/api/login",
                json={"username": "admin", "password": "Admin123!"}
            )
            assert login_response.status_code == 200
            
            # Access security dashboard page
            response = client.get("/security-dashboard")
            
            # Should return 200 OK
            assert response.status_code == 200
            
            # Verify required UI elements are present
            html = response.text
            
            # Metrics cards
            assert "Blocked Attacks" in html
            assert "Active Robots" in html
            assert "Revoked Certificates" in html
            assert "Anomaly Detections" in html
            assert "Auth Failures" in html
            
            # Key rotation status
            assert "Key Rotation Status" in html
            assert "Last Rotation" in html
            assert "Next Rotation" in html
            assert "Active Sessions" in html
            
            # Charts
            assert "Security Metrics Trends" in html
            assert "Blocked Attacks by Type" in html
            assert "metrics-chart" in html
            assert "attack-types-chart" in html
            
            # Alert feed
            assert "Alert Feed" in html
            assert "alert-feed" in html
            
            # Filters
            assert "Time Range" in html
            assert "Robot ID" in html
            assert "Category" in html
    
    def test_security_dashboard_page_operator_access(self):
        """Test that operator role can access security dashboard page."""
        with TestClient(app) as client:
            # Login as operator
            login_response = client.post(
                "/api/login",
                json={"username": "operator", "password": "Operator123!"}
            )
            assert login_response.status_code == 200
            
            # Operator should be able to access security dashboard
            response = client.get("/security-dashboard")
            assert response.status_code == 200
    
    def test_security_dashboard_page_auditor_access(self):
        """Test that auditor role can access security dashboard page."""
        with TestClient(app) as client:
            # Login as auditor
            login_response = client.post(
                "/api/login",
                json={"username": "auditor", "password": "Auditor123!"}
            )
            assert login_response.status_code == 200
            
            # Auditor should be able to access security dashboard
            response = client.get("/security-dashboard")
            assert response.status_code == 200
    
    def test_security_dashboard_page_includes_websocket_endpoints(self):
        """Test that security dashboard page references WebSocket endpoints."""
        with TestClient(app) as client:
            # Login as admin
            login_response = client.post(
                "/api/login",
                json={"username": "admin", "password": "Admin123!"}
            )
            assert login_response.status_code == 200
            
            # Access security dashboard page
            response = client.get("/security-dashboard")
            
            # Should return 200 OK
            assert response.status_code == 200
            
            # Verify WebSocket endpoints are referenced in JavaScript
            html = response.text
            # The JavaScript file should be included which contains WebSocket logic
            assert "security_dashboard.js" in html


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
