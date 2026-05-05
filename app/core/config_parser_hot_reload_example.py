"""
Example demonstrating configuration hot-reload functionality.

This example shows how to:
1. Load initial configuration
2. Register callbacks for configuration changes
3. Reload configuration without restart
4. Handle reload errors gracefully
5. Integrate with audit logger

Requirements: 21.5, 21.6
"""

import tempfile
import time
from pathlib import Path

from app.core.config_parser import SecurityConfigParser, SecurityConfig
from app.core.audit_logger import AuditLogger


def on_config_change(new_config: SecurityConfig):
    """Callback invoked when configuration changes."""
    print(f"\n[CALLBACK] Configuration changed!")
    print(f"  - TLS enabled: {new_config.tls_config is not None}")
    print(f"  - Rate limit policies: {len(new_config.rate_limit_policies)}")
    print(f"  - MFA requirements: {new_config.mfa_requirements}")


def main():
    print("=" * 70)
    print("Configuration Hot-Reload Example")
    print("=" * 70)
    
    # Create temporary certificate files for testing
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
        cert_file.write("FAKE CERT FOR DEMO")
        cert_path = cert_file.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as key_file:
        key_file.write("FAKE KEY FOR DEMO")
        key_path = key_file.name
    
    # Create temporary config file
    config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
    config_path = config_file.name
    config_file.close()
    
    try:
        # Initialize audit logger
        print("\n1. Initializing audit logger...")
        audit_logger = AuditLogger(
            signing_key_path="demo_signing_key.pem",
            genesis_hash_path="demo_genesis.txt",
            storage_path="demo_audit.json"
        )
        
        # Initialize config parser with audit logger
        print("2. Initializing config parser with audit logger...")
        parser = SecurityConfigParser(audit_logger=audit_logger)
        
        # Register callback for config changes
        print("3. Registering configuration change callback...")
        parser.register_config_change_callback(on_config_change)
        
        # Write initial configuration
        print("\n4. Loading initial configuration...")
        initial_config = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
  protocols:
    - TLSv1.2
    - TLSv1.3

key_rotation:
  rotation_interval_hours: 24
  grace_period_minutes: 5
  auto_rotate_master_key: false

mfa_requirements:
  admin: true
  operator: false
"""
        with open(config_path, 'w') as f:
            f.write(initial_config)
        
        config = parser.parse_config(config_path)
        print(f"   ✓ Configuration loaded successfully")
        print(f"   - Key rotation interval: {config.key_rotation_policy.rotation_interval_hours}h")
        print(f"   - MFA requirements: {config.mfa_requirements}")
        
        # Simulate some time passing
        time.sleep(1)
        
        # Update configuration file
        print("\n5. Updating configuration file...")
        updated_config = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
  protocols:
    - TLSv1.2
    - TLSv1.3

key_rotation:
  rotation_interval_hours: 48
  grace_period_minutes: 10
  auto_rotate_master_key: true

rate_limits:
  - endpoint_pattern: "/api/tasks/*"
    requests_per_window: 100
    window_seconds: 60
  - endpoint_pattern: "/api/robots/*"
    requests_per_window: 50
    window_seconds: 60

mfa_requirements:
  admin: true
  operator: true
  robot: false
"""
        with open(config_path, 'w') as f:
            f.write(updated_config)
        
        print("   ✓ Configuration file updated")
        
        # Hot-reload configuration
        print("\n6. Hot-reloading configuration (no restart required)...")
        success, error = parser.reload_config()
        
        if success:
            print("   ✓ Configuration reloaded successfully!")
            new_config = parser.get_current_config()
            print(f"   - Key rotation interval: {new_config.key_rotation_policy.rotation_interval_hours}h")
            print(f"   - Auto rotate master key: {new_config.key_rotation_policy.auto_rotate_master_key}")
            print(f"   - Rate limit policies: {len(new_config.rate_limit_policies)}")
            print(f"   - MFA requirements: {new_config.mfa_requirements}")
        else:
            print(f"   ✗ Configuration reload failed: {error}")
        
        # Demonstrate error handling
        print("\n7. Testing error handling with invalid configuration...")
        invalid_config = """
rate_limits:
  - endpoint_pattern: "/api/*"
    requests_per_window: -10
    window_seconds: 60
"""
        with open(config_path, 'w') as f:
            f.write(invalid_config)
        
        success, error = parser.reload_config()
        
        if not success:
            print(f"   ✓ Invalid configuration rejected (as expected)")
            print(f"   - Error: {error[:100]}...")
            print(f"   - Previous valid configuration still active")
            
            current_config = parser.get_current_config()
            print(f"   - Current key rotation interval: {current_config.key_rotation_policy.rotation_interval_hours}h")
        
        # Show audit log
        print("\n8. Audit log entries:")
        config_events = audit_logger.get_events_by_category("configuration")
        for i, event in enumerate(config_events, 1):
            print(f"   {i}. {event.title}")
            print(f"      - Actor: {event.actor}")
            print(f"      - Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event.timestamp))}")
            if 'changes' in event.details:
                changes = event.details['changes']
                if changes.get('type') == 'initial_load':
                    print(f"      - Type: Initial load")
                elif changes.get('type') == 'no_changes':
                    print(f"      - Type: No changes")
                else:
                    print(f"      - Changes: {list(changes.keys())}")
        
        # Verify audit chain integrity
        print("\n9. Verifying audit chain integrity...")
        valid, tampered_index = audit_logger.verify_chain_integrity()
        if valid:
            print(f"   ✓ Audit chain is valid ({audit_logger.get_event_count()} events)")
        else:
            print(f"   ✗ Audit chain tampered at index {tampered_index}")
        
        print("\n" + "=" * 70)
        print("Hot-Reload Example Complete!")
        print("=" * 70)
        print("\nKey Features Demonstrated:")
        print("  ✓ Configuration hot-reload without restart (Requirement 21.5)")
        print("  ✓ Audit logging of configuration changes (Requirement 21.6)")
        print("  ✓ Graceful error handling for invalid configurations")
        print("  ✓ Configuration change callbacks")
        print("  ✓ Preservation of valid config when reload fails")
        
    finally:
        # Cleanup
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)
        Path(config_path).unlink(missing_ok=True)
        Path("demo_signing_key.pem").unlink(missing_ok=True)
        Path("demo_genesis.txt").unlink(missing_ok=True)
        Path("demo_audit.json").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
