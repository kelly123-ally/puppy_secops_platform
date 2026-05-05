"""
Unit tests for TLSWebSocketServer

Tests TLS initialization, connection handling, certificate validation,
cipher suite enforcement, and certificate hot-reload functionality.

Validates Requirements:
- 1.1: TLS 1.2 and TLS 1.3 protocol support
- 1.2: Rejection of unencrypted connections
- 1.3: Strong cipher suite enforcement
- 1.4: TLS handshake verification
- 1.5: Certificate loading from secure storage
- 1.6: TLS initialization failure handling
"""

import asyncio
import ssl
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

from app.core.tls_websocket_server import TLSWebSocketServer


@pytest.fixture
def temp_cert_files():
    """Generate temporary self-signed certificate and key for testing."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Write to temporary files
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_path = cert_file.name
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        key_path = key_file.name
    
    yield cert_path, key_path
    
    # Cleanup
    Path(cert_path).unlink(missing_ok=True)
    Path(key_path).unlink(missing_ok=True)


class TestTLSWebSocketServerInitialization:
    """Test TLS WebSocket server initialization and configuration."""
    
    def test_init_with_valid_certificates(self, temp_cert_files):
        """Test initialization with valid certificate files (Requirement 1.5)."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=8765,
            cert_path=cert_path,
            key_path=key_path
        )
        
        assert server.host == "localhost"
        assert server.port == 8765
        assert server.cert_path == Path(cert_path)
        assert server.key_path == Path(key_path)
        assert not server.is_running
    
    def test_init_with_missing_certificate(self, temp_cert_files):
        """Test initialization fails with missing certificate file."""
        _, key_path = temp_cert_files
        
        with pytest.raises(FileNotFoundError, match="Certificate file not found"):
            TLSWebSocketServer(
                host="localhost",
                port=8765,
                cert_path="/nonexistent/cert.pem",
                key_path=key_path
            )
    
    def test_init_with_missing_key(self, temp_cert_files):
        """Test initialization fails with missing key file."""
        cert_path, _ = temp_cert_files
        
        with pytest.raises(FileNotFoundError, match="Private key file not found"):
            TLSWebSocketServer(
                host="localhost",
                port=8765,
                cert_path=cert_path,
                key_path="/nonexistent/key.pem"
            )
    
    def test_init_with_custom_handler(self, temp_cert_files):
        """Test initialization with custom connection handler."""
        cert_path, key_path = temp_cert_files
        
        async def custom_handler(websocket):
            pass
        
        server = TLSWebSocketServer(
            host="localhost",
            port=8765,
            cert_path=cert_path,
            key_path=key_path,
            handler=custom_handler
        )
        
        assert server.handler == custom_handler


class TestTLSConfiguration:
    """Test TLS protocol and cipher suite configuration."""
    
    def test_ssl_context_creation(self, temp_cert_files):
        """Test SSL context is created with correct TLS versions (Requirement 1.1)."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=8765,
            cert_path=cert_path,
            key_path=key_path
        )
        
        context = server._create_ssl_context()
        
        # Verify minimum TLS version is 1.2
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        
        # Verify TLS 1.3 is enabled if available
        if hasattr(ssl.TLSVersion, 'TLSv1_3'):
            assert context.maximum_version == ssl.TLSVersion.TLSv1_3
    
    def test_strong_cipher_suites(self, temp_cert_files):
        """Test that only strong cipher suites are enabled (Requirement 1.3)."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=8765,
            cert_path=cert_path,
            key_path=key_path
        )
        
        context = server._create_ssl_context()
        ciphers = context.get_ciphers()
        
        # Verify no weak ciphers are present
        weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'ANON']
        
        for cipher in ciphers:
            cipher_name = cipher.get('name', '').upper()
            for pattern in weak_patterns:
                assert pattern not in cipher_name, \
                    f"Weak cipher {pattern} found in {cipher_name}"
    
    def test_validate_tls_config_success(self, temp_cert_files):
        """Test TLS configuration validation succeeds with valid config."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=8765,
            cert_path=cert_path,
            key_path=key_path
        )
        
        is_valid, message = server.validate_tls_config()
        
        assert is_valid
        assert "strong ciphers available" in message.lower()
    
    def test_validate_tls_config_detects_weak_ciphers(self, temp_cert_files):
        """Test TLS validation detects weak cipher configurations."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=8765,
            cert_path=cert_path,
            key_path=key_path
        )
        
        # Mock context to return weak ciphers
        with patch.object(server, '_create_ssl_context') as mock_create:
            mock_context = MagicMock()
            mock_context.minimum_version = ssl.TLSVersion.TLSv1_2
            mock_context.get_ciphers.return_value = [
                {'name': 'RC4-SHA'},  # Weak cipher
            ]
            mock_create.return_value = mock_context
            
            is_valid, message = server.validate_tls_config()
            
            assert not is_valid
            assert "weak cipher" in message.lower()
            assert "RC4" in message


class TestServerLifecycle:
    """Test server start, stop, and lifecycle management."""
    
    @pytest.mark.asyncio
    async def test_start_server_success(self, temp_cert_files):
        """Test server starts successfully with valid TLS config."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,  # Use random available port
            cert_path=cert_path,
            key_path=key_path
        )
        
        await server.start()
        
        assert server.is_running
        assert server.address is not None
        
        await server.stop()
    
    @pytest.mark.asyncio
    async def test_start_server_with_invalid_cert(self, temp_cert_files):
        """Test server fails to start with invalid certificate (Requirement 1.6)."""
        _, key_path = temp_cert_files
        
        # Create invalid certificate file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
            f.write("INVALID CERTIFICATE DATA")
            invalid_cert = f.name
        
        try:
            server = TLSWebSocketServer(
                host="localhost",
                port=0,
                cert_path=invalid_cert,
                key_path=key_path
            )
            
            with pytest.raises(ssl.SSLError):
                await server.start()
            
            assert not server.is_running
        finally:
            Path(invalid_cert).unlink(missing_ok=True)
    
    @pytest.mark.asyncio
    async def test_start_server_already_running(self, temp_cert_files):
        """Test starting server twice raises error."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        await server.start()
        
        with pytest.raises(RuntimeError, match="already running"):
            await server.start()
        
        await server.stop()
    
    @pytest.mark.asyncio
    async def test_stop_server(self, temp_cert_files):
        """Test server stops gracefully."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        await server.start()
        assert server.is_running
        
        await server.stop()
        assert not server.is_running
        assert server.address is None
    
    @pytest.mark.asyncio
    async def test_stop_server_not_running(self, temp_cert_files):
        """Test stopping server that's not running doesn't raise error."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        # Should not raise error
        await server.stop()


class TestConnectionHandling:
    """Test WebSocket connection handling and TLS verification."""
    
    @pytest.mark.asyncio
    async def test_reject_unencrypted_connection(self, temp_cert_files):
        """Test unencrypted connections are rejected (Requirement 1.2)."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        # Mock WebSocket with no SSL
        mock_websocket = AsyncMock()
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = None  # No SSL object
        mock_websocket.transport = mock_transport
        mock_websocket.remote_address = ("127.0.0.1", 12345)
        
        await server._handle_connection(mock_websocket)
        
        # Verify connection was closed
        mock_websocket.close.assert_called_once()
        call_args = mock_websocket.close.call_args
        assert call_args[1]['code'] == 1002
        assert "TLS required" in call_args[1]['reason']
    
    @pytest.mark.asyncio
    async def test_verify_tls_handshake(self, temp_cert_files):
        """Test TLS handshake verification (Requirement 1.4)."""
        cert_path, key_path = temp_cert_files
        
        handler_called = False
        
        async def test_handler(websocket):
            nonlocal handler_called
            handler_called = True
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path,
            handler=test_handler
        )
        
        # Mock WebSocket with valid TLS
        mock_websocket = AsyncMock()
        mock_transport = MagicMock()
        mock_ssl_object = MagicMock()
        mock_ssl_object.cipher.return_value = ("AES256-GCM-SHA384", "TLSv1.3", 256)
        mock_transport.get_extra_info.return_value = mock_ssl_object
        mock_websocket.transport = mock_transport
        mock_websocket.remote_address = ("127.0.0.1", 12345)
        
        await server._handle_connection(mock_websocket)
        
        # Verify handler was called (connection accepted)
        assert handler_called
        mock_websocket.close.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_reject_incomplete_tls_handshake(self, temp_cert_files):
        """Test connections with incomplete TLS handshake are rejected."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        # Mock WebSocket with SSL object but no cipher (incomplete handshake)
        mock_websocket = AsyncMock()
        mock_transport = MagicMock()
        mock_ssl_object = MagicMock()
        mock_ssl_object.cipher.return_value = None  # Handshake incomplete
        mock_transport.get_extra_info.return_value = mock_ssl_object
        mock_websocket.transport = mock_transport
        mock_websocket.remote_address = ("127.0.0.1", 12345)
        
        await server._handle_connection(mock_websocket)
        
        # Verify connection was closed
        mock_websocket.close.assert_called_once()
        call_args = mock_websocket.close.call_args
        assert call_args[1]['code'] == 1002
        assert "handshake failed" in call_args[1]['reason'].lower()
    
    @pytest.mark.asyncio
    async def test_connection_without_transport(self, temp_cert_files):
        """Test connections without transport are rejected."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        # Mock WebSocket with no transport
        mock_websocket = AsyncMock()
        mock_websocket.transport = None
        
        await server._handle_connection(mock_websocket)
        
        # Verify connection was closed
        mock_websocket.close.assert_called_once()


class TestCertificateHotReload:
    """Test certificate hot-reload functionality."""
    
    def test_reload_certificates_success(self, temp_cert_files):
        """Test certificates can be reloaded without restart."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        # Mock running server
        server.server = MagicMock()
        server._ssl_context = MagicMock()
        
        result = server.reload_certificates()
        
        assert result is True
    
    def test_reload_certificates_not_running(self, temp_cert_files):
        """Test reload fails when server is not running."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        result = server.reload_certificates()
        
        assert result is False
    
    def test_reload_certificates_validation_failure(self, temp_cert_files):
        """Test reload rolls back on validation failure."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        # Mock running server
        old_context = MagicMock()
        server.server = MagicMock()
        server._ssl_context = old_context
        
        # Mock validation failure
        with patch.object(server, 'validate_tls_config') as mock_validate:
            mock_validate.return_value = (False, "Invalid config")
            
            result = server.reload_certificates()
            
            assert result is False
            # Verify rollback to old context
            assert server._ssl_context == old_context


class TestServerProperties:
    """Test server property accessors."""
    
    def test_is_running_property(self, temp_cert_files):
        """Test is_running property reflects server state."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=0,
            cert_path=cert_path,
            key_path=key_path
        )
        
        assert not server.is_running
        
        server.server = MagicMock()
        assert server.is_running
        
        server.server = None
        assert not server.is_running
    
    def test_address_property(self, temp_cert_files):
        """Test address property returns server address."""
        cert_path, key_path = temp_cert_files
        
        server = TLSWebSocketServer(
            host="localhost",
            port=8765,
            cert_path=cert_path,
            key_path=key_path
        )
        
        assert server.address is None
        
        server.server = MagicMock()
        assert server.address == ("localhost", 8765)
        
        server.server = None
        assert server.address is None
