"""
Example usage of TLSWebSocketServer

This example demonstrates how to:
1. Create a TLS WebSocket server with certificate files
2. Handle incoming connections
3. Start and stop the server
4. Reload certificates without restart
"""

import asyncio
import logging
from pathlib import Path

from app.core.tls_websocket_server import TLSWebSocketServer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def echo_handler(websocket):
    """
    Simple echo handler that receives messages and sends them back.
    
    Args:
        websocket: WebSocket connection
    """
    logger.info(f"Client connected: {websocket.remote_address}")
    
    try:
        async for message in websocket:
            logger.info(f"Received: {message}")
            await websocket.send(f"Echo: {message}")
    except Exception as e:
        logger.error(f"Error in handler: {e}")
    finally:
        logger.info(f"Client disconnected: {websocket.remote_address}")


async def main():
    """Main example demonstrating TLS WebSocket server usage."""
    
    # Certificate paths (use existing CA certificate for demo)
    cert_path = Path("ca_cert.pem")
    key_path = Path("ca_key.pem")
    
    # Verify certificate files exist
    if not cert_path.exists() or not key_path.exists():
        logger.error(
            "Certificate files not found. Please ensure ca_cert.pem and "
            "ca_key.pem exist in the project root."
        )
        return
    
    # Create TLS WebSocket server
    server = TLSWebSocketServer(
        host="localhost",
        port=8765,
        cert_path=str(cert_path),
        key_path=str(key_path),
        handler=echo_handler
    )
    
    # Validate TLS configuration before starting
    is_valid, message = server.validate_tls_config()
    if not is_valid:
        logger.error(f"TLS configuration invalid: {message}")
        return
    
    logger.info(f"TLS configuration valid: {message}")
    
    try:
        # Start the server
        await server.start()
        logger.info(f"Server running at wss://{server.host}:{server.port}")
        logger.info("Press Ctrl+C to stop the server")
        
        # Keep server running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        # Gracefully stop the server
        await server.stop()
        logger.info("Server stopped")


async def certificate_reload_example():
    """
    Example demonstrating certificate hot-reload functionality.
    
    This allows updating certificates without restarting the server,
    which is useful for certificate renewal.
    """
    cert_path = Path("ca_cert.pem")
    key_path = Path("ca_key.pem")
    
    if not cert_path.exists() or not key_path.exists():
        logger.error("Certificate files not found")
        return
    
    server = TLSWebSocketServer(
        host="localhost",
        port=8765,
        cert_path=str(cert_path),
        key_path=str(key_path),
        handler=echo_handler
    )
    
    await server.start()
    logger.info("Server started")
    
    # Simulate certificate renewal after some time
    await asyncio.sleep(5)
    
    logger.info("Reloading certificates...")
    success = server.reload_certificates()
    
    if success:
        logger.info("Certificates reloaded successfully")
    else:
        logger.error("Certificate reload failed")
    
    await server.stop()


if __name__ == "__main__":
    # Run the main example
    asyncio.run(main())
    
    # Uncomment to run certificate reload example instead:
    # asyncio.run(certificate_reload_example())
