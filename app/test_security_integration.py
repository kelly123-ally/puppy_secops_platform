"""
Integration test for security components initialization in main.py

Tests that all security components are properly initialized and wired together.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


class TestSecurityIntegration:
    """Test security components integration in application startup."""
    
    def test_security_components_initialized(self):
        """Test that all security components are initialized during startup."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        from app.main import app
        
        with TestClient(app) as client:
            # Verify KeyManager is initialized
            assert hasattr(app.state, 'key_manager')
            assert app.state.key_manager is not None
            
            # Verify CertificateManager is initialized
            assert hasattr(app.state, 'certificate_manager')
            assert app.state.certificate_manager is not None
            
            # Verify AuditLogger is initialized
            assert hasattr(app.state, 'audit_logger')
            assert app.state.audit_logger is not None
            
            # Verify AlertSystem is initialized
            assert hasattr(app.state, 'alert_system')
            assert app.state.alert_system is not None
            
            # Verify AnomalyDetector is initialized
            assert hasattr(app.state, 'anomaly_detector')
            assert app.state.anomaly_detector is not None
            
            # Verify AccessController is initialized
            assert hasattr(app.state, 'access_controller')
            assert app.state.access_controller is not None
    
    def test_security_dashboard_api_initialized_with_components(self):
        """Test that SecurityDashboardAPI is initialized with all security components."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        from app.main import app
        
        with TestClient(app) as client:
            # Verify SecurityDashboardAPI is initialized
            assert hasattr(app.state, 'dashboard_api')
            assert app.state.dashboard_api is not None
            
            # Verify dashboard API has all components
            dashboard_api = app.state.dashboard_api
            assert dashboard_api.alert_system is not None
            assert dashboard_api.audit_logger is not None
            assert dashboard_api.certificate_manager is not None
            assert dashboard_api.key_manager is not None
            assert dashboard_api.anomaly_detector is not None
            assert dashboard_api.access_controller is not None
    
    def test_simulator_has_anomaly_detector_and_alert_system(self):
        """Test that FleetSimulator is wired with anomaly detector and alert system."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        from app.main import app
        
        with TestClient(app) as client:
            # Verify simulator has anomaly detector
            assert hasattr(app.state.simulator, 'anomaly_detector')
            assert app.state.simulator.anomaly_detector is not None
            
            # Verify simulator has alert system
            assert hasattr(app.state.simulator, 'alert_system')
            assert app.state.simulator.alert_system is not None
            
            # Verify they are the same instances as in app state
            assert app.state.simulator.anomaly_detector is app.state.anomaly_detector
            assert app.state.simulator.alert_system is app.state.alert_system
    
    def test_audit_logger_wired_to_components(self):
        """Test that audit logger is properly wired to other components."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        from app.main import app
        
        with TestClient(app) as client:
            # Verify KeyManager has audit logger
            assert app.state.key_manager.audit_logger is not None
            assert app.state.key_manager.audit_logger is app.state.audit_logger
            
            # Verify CertificateManager has audit logger
            assert app.state.certificate_manager.audit_logger is not None
            assert app.state.certificate_manager.audit_logger is app.state.audit_logger
            
            # Verify AccessController has audit logger
            assert app.state.access_controller.audit_logger is not None
            assert app.state.access_controller.audit_logger is app.state.audit_logger
    
    def test_access_controller_has_default_roles(self):
        """Test that AccessController is initialized with default roles."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        from app.main import app
        
        with TestClient(app) as client:
            access_controller = app.state.access_controller
            
            # Verify default roles are present
            assert "admin" in access_controller.roles
            assert "operator" in access_controller.roles
            assert "robot" in access_controller.roles
            
            # Verify rate limit policies are configured
            assert len(access_controller.rate_limit_policies) > 0
    
    def test_alert_system_has_default_rules(self):
        """Test that AlertSystem is initialized with default alert rules."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        from app.main import app
        
        with TestClient(app) as client:
            alert_system = app.state.alert_system
            
            # Verify default alert rules are present
            assert len(alert_system.rules) >= 2  # At least CRITICAL_EVENTS_RULE and HIGH_SEVERITY_RULE
            
            # Verify rules are enabled
            enabled_rules = [rule for rule in alert_system.rules if rule.enabled]
            assert len(enabled_rules) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
