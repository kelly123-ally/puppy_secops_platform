"""
Integration test for TLS startup in main.py

Tests the complete application startup with TLS configuration.
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


class TestTLSStartup:
    """Test application startup with TLS configuration."""
    
    def test_app_starts_with_tls_certificates(self):
        """Test that application starts successfully when TLS certificates are present."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        # Import app after ensuring certificates exist
        from app.main import app
        
        # Create test client (this triggers lifespan startup)
        with TestClient(app) as client:
            # Verify app state has SSL context
            assert hasattr(app.state, 'ssl_context')
            assert app.state.ssl_context is not None
            
            # Verify basic endpoint works
            response = client.get("/")
            assert response.status_code in [200, 302]  # 302 for redirect to /app
    
    def test_app_starts_without_tls_certificates(self):
        """Test that application starts with warning when certificates are missing."""
        with patch.dict(os.environ, {"TLS_CERT_PATH": "nonexistent.pem", "TLS_KEY_PATH": "nonexistent.pem"}):
            # Import app with missing certificates
            from app.main import app
            
            # Create test client
            with TestClient(app) as client:
                # Verify app state has None SSL context
                assert hasattr(app.state, 'ssl_context')
                assert app.state.ssl_context is None
                
                # Verify basic endpoint still works
                response = client.get("/")
                assert response.status_code in [200, 302]
    
    def test_app_fails_with_invalid_tls_config(self):
        """Test that application fails to start with invalid TLS configuration."""
        import tempfile
        
        # Create invalid certificate files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_file.write("INVALID CERTIFICATE")
            cert_path = cert_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as key_file:
            key_file.write("INVALID KEY")
            key_path = key_file.name
        
        try:
            with patch.dict(os.environ, {"TLS_CERT_PATH": cert_path, "TLS_KEY_PATH": key_path}):
                # Import should fail during lifespan startup
                from app.main import app
                
                with pytest.raises(RuntimeError, match="TLS initialization failed"):
                    with TestClient(app):
                        pass
        finally:
            Path(cert_path).unlink()
            Path(key_path).unlink()
    
    def test_tls_context_stored_in_app_state(self):
        """Test that TLS context is properly stored in app state."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        from app.main import app
        
        with TestClient(app) as client:
            # Verify SSL context is stored
            assert hasattr(app.state, 'ssl_context')
            
            # Verify other state is also initialized
            assert hasattr(app.state, 'sessions')
            assert hasattr(app.state, 'simulator')
            assert hasattr(app.state, 'hub')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
