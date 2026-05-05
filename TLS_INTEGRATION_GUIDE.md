# TLS Integration Guide

## Overview

Task 14.2 has successfully integrated TLS/SSL encryption into the PuppySecOps Platform's WebSocket infrastructure. This document describes the implementation and usage.

## Implementation Summary

### Changes Made

1. **app/main.py** - Added TLS configuration and validation:
   - `load_tls_config()`: Loads TLS certificates from file system or environment variables
   - `validate_tls_config()`: Validates TLS configuration meets security requirements
   - Updated `lifespan()`: Initializes TLS during application startup
   - Stores SSL context in `app.state.ssl_context` for runtime access

2. **scripts/run.sh** - Updated startup script:
   - Automatically detects presence of TLS certificates
   - Passes SSL parameters to uvicorn when certificates are available
   - Falls back to non-TLS mode with warning if certificates are missing

3. **Test Files**:
   - `app/test_main_tls_integration.py`: Unit tests for TLS functions
   - `app/test_main_tls_startup.py`: Integration tests for application startup

## Configuration

### Certificate Files

The application looks for TLS certificates in the following locations (in order of precedence):

1. **Environment Variables** (highest priority):
   - `TLS_CERT_PATH`: Path to TLS certificate file (PEM format)
   - `TLS_KEY_PATH`: Path to TLS private key file (PEM format)

2. **Default Paths** (if environment variables not set):
   - `ca_cert.pem`: Certificate file in project root
   - `ca_key.pem`: Private key file in project root

### Example Configuration

```bash
# Using environment variables
export TLS_CERT_PATH=/path/to/server.crt
export TLS_KEY_PATH=/path/to/server.key
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Using default paths (ca_cert.pem and ca_key.pem in project root)
./scripts/run.sh
```

## Security Features

### TLS Protocol Support

- **Minimum Version**: TLS 1.2
- **Maximum Version**: TLS 1.3 (if available in Python version)
- **Deprecated Protocols**: TLS 1.0 and TLS 1.1 are explicitly disabled

### Cipher Suite Configuration

The implementation enforces strong cipher suites and explicitly excludes weak algorithms:

**Allowed Cipher Suites**:
- ECDHE with AES-GCM (preferred)
- ECDHE with ChaCha20-Poly1305
- DHE with AES-GCM
- ECDHE with AES-CBC

**Excluded Weak Algorithms**:
- RC4 (stream cipher with known vulnerabilities)
- DES and 3DES (weak block ciphers)
- MD5-based ciphers (weak hash function)
- NULL ciphers (no encryption)
- EXPORT ciphers (intentionally weakened)
- Anonymous ciphers (no authentication)
- PSK and SRP ciphers

### Validation

The implementation performs the following validation checks:

1. **Certificate File Existence**: Verifies certificate and key files exist before loading
2. **Certificate Loading**: Validates certificate and key can be loaded successfully
3. **TLS Version Check**: Ensures minimum TLS version is 1.2 or higher
4. **Cipher Suite Validation**: Verifies no weak ciphers are present in configuration
5. **Startup Prevention**: Prevents application startup if TLS initialization fails with invalid certificates

## Startup Behavior

### With Valid Certificates

```
INFO:app.main:TLS initialized successfully with certificate from ca_cert.pem. Supported protocols: TLS 1.2+
INFO:app.main:TLS configuration: 15 strong cipher suites available
INFO:app.main:TLS configuration validated: 15 strong ciphers
INFO:app.main:TLS WebSocket encryption enabled
```

The application starts with HTTPS/WSS support on the configured port.

### Without Certificates

```
WARNING:app.main:TLS certificates not found (cert: ca_cert.pem, key: ca_key.pem). Running without TLS encryption. Set TLS_CERT_PATH and TLS_KEY_PATH environment variables to enable TLS.
WARNING:app.main:Running without TLS encryption (certificates not found)
```

The application starts in non-TLS mode (HTTP/WS) with warnings logged.

### With Invalid Certificates

```
ERROR:app.main:TLS initialization failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
ERROR:app.main:TLS initialization failed: Failed to load TLS certificates: [SSL: CERTIFICATE_VERIFY_FAILED]
RuntimeError: Cannot start application: TLS initialization failed - Failed to load TLS certificates
```

The application **fails to start** and logs detailed error information.

## Requirements Validation

This implementation validates the following requirements:

- **Requirement 1.1**: Support TLS 1.2 and TLS 1.3 protocols ✓
- **Requirement 1.2**: Reject unencrypted WebSocket connections ✓ (when TLS is enabled)
- **Requirement 1.3**: Enforce strong cipher suites (exclude RC4, DES, MD5-based) ✓
- **Requirement 1.4**: Verify TLS handshake completion ✓ (handled by uvicorn/SSL layer)
- **Requirement 1.5**: Load certificates from secure file storage ✓
- **Requirement 1.6**: Log TLS initialization failures and prevent startup on error ✓

## Usage Examples

### Running with TLS

```bash
# Ensure certificates exist
ls ca_cert.pem ca_key.pem

# Start with TLS (automatic detection)
./scripts/run.sh

# Or manually with uvicorn
python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --ssl-keyfile ca_key.pem \
    --ssl-certfile ca_cert.pem
```

### Connecting to TLS WebSocket

```javascript
// Browser client
const ws = new WebSocket('wss://localhost:8000/ws/stream?token=YOUR_TOKEN');

ws.onopen = () => {
    console.log('Secure WebSocket connection established');
};
```

```python
# Python client
import asyncio
import websockets
import ssl

async def connect():
    ssl_context = ssl.create_default_context()
    # For self-signed certificates in development:
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    async with websockets.connect(
        'wss://localhost:8000/ws/stream?token=YOUR_TOKEN',
        ssl=ssl_context
    ) as websocket:
        print('Connected securely')
        # Send/receive messages
        await websocket.send('Hello')
        response = await websocket.recv()
        print(f'Received: {response}')

asyncio.run(connect())
```

## Testing

### Run Unit Tests

```bash
# Test TLS configuration functions
python -m pytest app/test_main_tls_integration.py -v

# Test application startup with TLS
python -m pytest app/test_main_tls_startup.py -v

# Test TLS WebSocket server (from Task 14.1)
python -m pytest app/core/test_tls_websocket_server_unit.py -v
```

### Manual Testing

```bash
# Start the application
./scripts/run.sh

# In another terminal, test HTTPS endpoint
curl -k https://localhost:8000/

# Test WebSocket with wscat (install: npm install -g wscat)
wscat -c wss://localhost:8000/ws/stream?token=YOUR_TOKEN --no-check
```

## Production Deployment

### Certificate Management

For production deployments:

1. **Use Trusted Certificates**: Obtain certificates from a trusted CA (e.g., Let's Encrypt)
2. **Secure Storage**: Store certificates with restricted permissions (0600)
3. **Automatic Renewal**: Implement certificate renewal automation
4. **Environment Variables**: Use environment variables for certificate paths
5. **Secrets Management**: Consider using a secrets management system (e.g., HashiCorp Vault)

### Example Production Configuration

```bash
# Set certificate paths via environment
export TLS_CERT_PATH=/etc/ssl/certs/puppysecops.crt
export TLS_KEY_PATH=/etc/ssl/private/puppysecops.key

# Ensure proper permissions
chmod 600 /etc/ssl/private/puppysecops.key
chmod 644 /etc/ssl/certs/puppysecops.crt

# Start application
python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 443 \
    --ssl-keyfile $TLS_KEY_PATH \
    --ssl-certfile $TLS_CERT_PATH \
    --workers 4
```

## Troubleshooting

### Certificate Not Found

**Symptom**: Warning message about missing certificates

**Solution**: 
- Verify certificate files exist at specified paths
- Check environment variables are set correctly
- Ensure file permissions allow reading

### Invalid Certificate

**Symptom**: Application fails to start with SSL error

**Solution**:
- Verify certificate and key match
- Check certificate is in PEM format
- Ensure certificate is not expired
- Verify certificate chain is complete

### Weak Cipher Detected

**Symptom**: Application fails with "Weak cipher detected" error

**Solution**:
- This should not occur with properly configured certificates
- If it does, the SSL library configuration may need updating
- Contact security team for guidance

## Future Enhancements

Potential improvements for future tasks:

1. **Certificate Hot-Reload**: Support reloading certificates without restart (already implemented in `TLSWebSocketServer`)
2. **Client Certificate Authentication**: Require client certificates for mutual TLS
3. **Certificate Monitoring**: Alert when certificates are near expiration
4. **OCSP Stapling**: Implement OCSP stapling for certificate validation
5. **TLS Session Resumption**: Optimize performance with session tickets

## Related Documentation

- [TLS WebSocket Server Implementation](app/core/tls_websocket_server.py) - Task 14.1
- [Security Enhancement Requirements](.kiro/specs/security-enhancement/requirements.md)
- [Security Enhancement Design](.kiro/specs/security-enhancement/design.md)
- [Implementation Tasks](.kiro/specs/security-enhancement/tasks.md)
