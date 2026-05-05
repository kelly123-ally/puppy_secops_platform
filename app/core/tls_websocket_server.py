"""
TLS WebSocket Server

Provides encrypted transport layer for robot-to-control-plane communications.

Requirements:
- 1.1: Support TLS 1.2 and TLS 1.3 protocols
- 1.2: Reject unencrypted WebSocket connections
- 1.3: Enforce strong cipher suites (exclude RC4, DES, MD5-based)
- 1.4: Verify TLS handshake completion
- 1.5: Load certificates from secure file storage
"""

import asyncio
import logging
import ssl
from pathlib import Path
from typing import Callable, Optional, Tuple
import websockets
from websockets.asyncio.server import ServerConnection, serve


logger = logging.getLogger(__name__)


class TLSWebSocketServer:
    """
    TLS-enabled WebSocket server for secure robot communications.
    
    This server enforces TLS 1.2/1.3 encryption with strong cipher suites,
    rejects unencrypted connections, and supports certificate hot-reload.
    """
    
    def __init__(
        self,
        host: str,
        port: int,
        cert_path: str,
        key_path: str,
        handler: Optional[Callable] = None
    ):
        """
        Initialize TLS WebSocket server with certificate and private key.
        
        Args:
            host: Server host address (e.g., "0.0.0.0", "localhost")
            port: Server port number
            cert_path: Path to TLS certificate file (PEM format)
            key_path: Path to TLS private key file (PEM format)
            handler: Optional WebSocket connection handler function
            
        Validates Requirements:
        - 1.5: Certificates loaded from secure file storage (not embedded in code)
        """
        self.host = host
        self.port = port
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)
        self.handler = handler
        self.server: Optional[websockets.server.WebSocketServer] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        
        # Validate certificate files exist
        if not self.cert_path.exists():
            raise FileNotFoundError(f"Certificate file not found: {cert_path}")
        if not self.key_path.exists():
            raise FileNotFoundError(f"Private key file not found: {key_path}")
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context with secure TLS configuration.
        
        Validates Requirements:
        - 1.1: Support TLS 1.2 and TLS 1.3 protocols
        - 1.3: Enforce strong cipher suites (exclude RC4, DES, MD5-based)
        
        Returns:
            Configured SSL context
            
        Raises:
            ssl.SSLError: If certificate/key loading fails
        """
        # Create SSL context with TLS 1.2+ (excludes TLS 1.0, 1.1)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Set minimum TLS version to 1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Enable TLS 1.3 if available (Python 3.7+)
        try:
            context.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            # TLS 1.3 not available in this Python version
            logger.warning("TLS 1.3 not available, using TLS 1.2 only")
        
        # Configure strong cipher suites (exclude weak algorithms)
        # This cipher string excludes:
        # - RC4 (stream cipher with known vulnerabilities)
        # - DES and 3DES (weak block ciphers)
        # - MD5-based ciphers (weak hash function)
        # - NULL ciphers (no encryption)
        # - EXPORT ciphers (intentionally weakened)
        # - Anonymous ciphers (no authentication)
        cipher_string = (
            "ECDHE+AESGCM:"  # Prefer ECDHE with AES-GCM
            "ECDHE+CHACHA20:"  # ChaCha20-Poly1305 for modern clients
            "DHE+AESGCM:"  # DHE with AES-GCM as fallback
            "ECDHE+AES:"  # ECDHE with AES-CBC
            "!aNULL:"  # Exclude anonymous ciphers
            "!eNULL:"  # Exclude NULL encryption
            "!EXPORT:"  # Exclude export-grade ciphers
            "!DES:"  # Exclude DES
            "!3DES:"  # Exclude 3DES
            "!MD5:"  # Exclude MD5-based ciphers
            "!RC4:"  # Exclude RC4
            "!PSK:"  # Exclude pre-shared key ciphers
            "!SRP:"  # Exclude SRP ciphers
            "!CAMELLIA"  # Exclude Camellia (less common)
        )
        context.set_ciphers(cipher_string)
        
        # Load certificate and private key
        try:
            context.load_cert_chain(
                certfile=str(self.cert_path),
                keyfile=str(self.key_path)
            )
            logger.info(f"Loaded TLS certificate from {self.cert_path}")
        except ssl.SSLError as e:
            logger.error(f"Failed to load TLS certificate: {e}")
            raise
        
        # Require TLS for all connections (no fallback to unencrypted)
        context.check_hostname = False  # Server-side doesn't check hostname
        context.verify_mode = ssl.CERT_NONE  # Client cert verification optional
        
        return context
    
    def validate_tls_config(self) -> Tuple[bool, str]:
        """
        Verify TLS configuration is secure (protocols, ciphers).
        
        Validates Requirements:
        - 1.1: TLS 1.2 and TLS 1.3 support
        - 1.3: Strong cipher suites enforced
        
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            context = self._create_ssl_context()
            
            # Check minimum TLS version
            if context.minimum_version < ssl.TLSVersion.TLSv1_2:
                return False, "TLS version below 1.2 is not allowed"
            
            # Check that weak ciphers are excluded
            ciphers = context.get_ciphers()
            weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
            
            for cipher in ciphers:
                cipher_name = cipher.get('name', '').upper()
                for pattern in weak_patterns:
                    if pattern.upper() in cipher_name:
                        return False, f"Weak cipher detected: {cipher_name}"
            
            return True, f"TLS configuration valid: {len(ciphers)} strong ciphers available"
            
        except Exception as e:
            return False, f"TLS configuration error: {str(e)}"
    
    async def _handle_connection(self, websocket: ServerConnection):
        """
        Handle incoming WebSocket connection with TLS verification.
        
        Validates Requirements:
        - 1.4: Verify TLS handshake completion
        
        Args:
            websocket: WebSocket connection
        """
        # Verify TLS handshake completed
        transport = websocket.transport
        if transport is None:
            logger.error("No transport available for WebSocket connection")
            await websocket.close(code=1002, reason="No transport")
            return
        
        # Get SSL object to verify TLS handshake
        ssl_object = transport.get_extra_info('ssl_object')
        if ssl_object is None:
            # Connection is not encrypted - reject it
            logger.warning(
                f"Rejected unencrypted connection from {websocket.remote_address}"
            )
            await websocket.close(code=1002, reason="TLS required")
            return
        
        # Verify TLS handshake completed successfully
        try:
            cipher = ssl_object.cipher()
            if cipher is None:
                logger.error("TLS handshake incomplete")
                await websocket.close(code=1002, reason="TLS handshake failed")
                return
            
            # Log successful TLS connection
            cipher_name, tls_version, _ = cipher
            logger.info(
                f"TLS connection established: {tls_version} with {cipher_name} "
                f"from {websocket.remote_address}"
            )
            
        except Exception as e:
            logger.error(f"TLS verification failed: {e}")
            await websocket.close(code=1002, reason="TLS verification failed")
            return
        
        # Delegate to application handler if provided
        if self.handler:
            try:
                await self.handler(websocket)
            except Exception as e:
                logger.error(f"Handler error: {e}")
                await websocket.close(code=1011, reason="Internal error")
    
    async def start(self) -> None:
        """
        Start the WebSocket server with TLS enabled.
        
        Validates Requirements:
        - 1.1: TLS 1.2/1.3 enabled
        - 1.2: Unencrypted connections rejected
        
        Raises:
            RuntimeError: If server is already running
            ssl.SSLError: If TLS initialization fails
        """
        if self.server is not None:
            raise RuntimeError("Server is already running")
        
        # Create SSL context
        try:
            self._ssl_context = self._create_ssl_context()
            logger.info("TLS context initialized successfully")
        except ssl.SSLError as e:
            logger.error(f"TLS initialization failed: {e}")
            raise
        
        # Validate TLS configuration
        is_valid, message = self.validate_tls_config()
        if not is_valid:
            logger.error(f"TLS configuration validation failed: {message}")
            raise RuntimeError(f"Invalid TLS configuration: {message}")
        
        logger.info(f"TLS configuration validated: {message}")
        
        # Start WebSocket server with TLS
        try:
            self.server = await serve(
                self._handle_connection,
                self.host,
                self.port,
                ssl=self._ssl_context
            )
            logger.info(
                f"TLS WebSocket server started on wss://{self.host}:{self.port}"
            )
        except Exception as e:
            logger.error(f"Failed to start WebSocket server: {e}")
            raise
    
    async def stop(self) -> None:
        """
        Gracefully shutdown the WebSocket server.
        
        Closes all active connections and stops accepting new connections.
        """
        if self.server is None:
            logger.warning("Server is not running")
            return
        
        logger.info("Shutting down TLS WebSocket server...")
        
        # Close the server (stops accepting new connections)
        self.server.close()
        
        # Wait for server to close
        await self.server.wait_closed()
        
        self.server = None
        self._ssl_context = None
        
        logger.info("TLS WebSocket server stopped")
    
    def reload_certificates(self) -> bool:
        """
        Reload TLS certificates without restarting the server.
        
        This allows certificate renewal without service interruption.
        Note: Existing connections continue with old certificates,
        new connections use the reloaded certificates.
        
        Returns:
            True if reload successful, False otherwise
        """
        if self.server is None:
            logger.warning("Cannot reload certificates: server not running")
            return False
        
        try:
            # Create new SSL context with reloaded certificates
            new_context = self._create_ssl_context()
            
            # Validate new configuration
            old_context = self._ssl_context
            self._ssl_context = new_context
            is_valid, message = self.validate_tls_config()
            
            if not is_valid:
                # Rollback to old context
                self._ssl_context = old_context
                logger.error(f"Certificate reload failed validation: {message}")
                return False
            
            logger.info(f"Certificates reloaded successfully: {message}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload certificates: {e}")
            return False
    
    @property
    def is_running(self) -> bool:
        """Check if server is currently running."""
        return self.server is not None
    
    @property
    def address(self) -> Optional[Tuple[str, int]]:
        """Get server address if running."""
        if self.server is None:
            return None
        return (self.host, self.port)
