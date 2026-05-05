"""
Unit tests for TLS integration in main.py

Tests TLS configuration loading, validation, and error handling.
"""

import os
import ssl
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.main import load_tls_config, validate_tls_config


class TestTLSIntegration:
    """Test TLS configuration loading and validation."""
    
    def test_load_tls_config_missing_certificates(self):
        """Test that missing certificates return None with warning."""
        with patch.dict(os.environ, {"TLS_CERT_PATH": "nonexistent.pem", "TLS_KEY_PATH": "nonexistent.pem"}):
            context = load_tls_config()
            assert context is None
    
    def test_load_tls_config_with_valid_certificates(self):
        """Test loading TLS config with valid certificate files."""
        # Use existing ca_cert.pem and ca_key.pem from project root
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        with patch.dict(os.environ, {"TLS_CERT_PATH": str(cert_path), "TLS_KEY_PATH": str(key_path)}):
            context = load_tls_config()
            
            assert context is not None
            assert isinstance(context, ssl.SSLContext)
            assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    
    def test_load_tls_config_invalid_certificate(self):
        """Test that invalid certificate raises RuntimeError."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_file.write("INVALID CERTIFICATE DATA")
            cert_path = cert_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as key_file:
            key_file.write("INVALID KEY DATA")
            key_path = key_file.name
        
        try:
            with patch.dict(os.environ, {"TLS_CERT_PATH": cert_path, "TLS_KEY_PATH": key_path}):
                with pytest.raises(RuntimeError, match="Failed to load TLS certificates"):
                    load_tls_config()
        finally:
            Path(cert_path).unlink()
            Path(key_path).unlink()
    
    def test_validate_tls_config_none_context(self):
        """Test that None context fails validation."""
        assert validate_tls_config(None) is False
    
    def test_validate_tls_config_valid_context(self):
        """Test validation of valid TLS context."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        with patch.dict(os.environ, {"TLS_CERT_PATH": str(cert_path), "TLS_KEY_PATH": str(key_path)}):
            context = load_tls_config()
            assert validate_tls_config(context) is True
    
    def test_validate_tls_config_weak_ciphers_rejected(self):
        """Test that weak ciphers are detected and rejected."""
        # Create a mock context with weak ciphers
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_context.minimum_version = ssl.TLSVersion.TLSv1_2
        mock_context.get_ciphers.return_value = [
            {"name": "ECDHE-RSA-AES128-GCM-SHA256"},
            {"name": "RC4-SHA"},  # Weak cipher
        ]
        
        assert validate_tls_config(mock_context) is False
    
    def test_tls_config_enforces_minimum_version(self):
        """Test that TLS 1.2 minimum version is enforced."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        with patch.dict(os.environ, {"TLS_CERT_PATH": str(cert_path), "TLS_KEY_PATH": str(key_path)}):
            context = load_tls_config()
            
            if context:
                assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    
    def test_tls_config_excludes_weak_ciphers(self):
        """Test that weak cipher patterns are excluded from configuration."""
        cert_path = Path("ca_cert.pem")
        key_path = Path("ca_key.pem")
        
        if not cert_path.exists() or not key_path.exists():
            pytest.skip("Certificate files not found in project root")
        
        with patch.dict(os.environ, {"TLS_CERT_PATH": str(cert_path), "TLS_KEY_PATH": str(key_path)}):
            context = load_tls_config()
            
            if context:
                ciphers = context.get_ciphers()
                weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                
                for cipher in ciphers:
                    cipher_name = cipher.get('name', '').upper()
                    for pattern in weak_patterns:
                        assert pattern.upper() not in cipher_name, \
                            f"Weak cipher pattern '{pattern}' found in {cipher_name}"
    
    def test_environment_variable_override(self):
        """Test that environment variables override default certificate paths."""
        custom_cert = "custom_cert.pem"
        custom_key = "custom_key.pem"
        
        with patch.dict(os.environ, {"TLS_CERT_PATH": custom_cert, "TLS_KEY_PATH": custom_key}):
            # Should return None since custom files don't exist
            context = load_tls_config()
            assert context is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
