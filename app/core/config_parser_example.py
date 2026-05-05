"""
Example usage of SecurityConfigParser

Demonstrates how to parse and validate security configuration files.
"""

from app.core.config_parser import SecurityConfigParser


def main():
    """Demonstrate SecurityConfigParser usage."""
    parser = SecurityConfigParser()
    
    # Parse the example configuration
    try:
        config = parser.parse_config("config/security_config_example.yaml")
        
        print("✓ Configuration parsed successfully!\n")
        
        # Display parsed configuration
        print("=== Security Configuration ===\n")
        
        if config.tls_config:
            print("TLS Configuration:")
            print(f"  Certificate: {config.tls_config.cert_path}")
            print(f"  Key: {config.tls_config.key_path}")
            print(f"  Protocols: {', '.join(config.tls_config.protocols)}")
            print()
        
        if config.key_rotation_policy:
            print("Key Rotation Policy:")
            print(f"  Interval: {config.key_rotation_policy.rotation_interval_hours} hours")
            print(f"  Grace Period: {config.key_rotation_policy.grace_period_minutes} minutes")
            print(f"  Auto-rotate Master Key: {config.key_rotation_policy.auto_rotate_master_key}")
            print()
        
        if config.rate_limit_policies:
            print(f"Rate Limit Policies ({len(config.rate_limit_policies)}):")
            for policy in config.rate_limit_policies:
                print(f"  - {policy.endpoint_pattern}: {policy.requests_per_window} requests per {policy.window_seconds}s")
                if policy.role_overrides:
                    print(f"    Role overrides: {policy.role_overrides}")
            print()
        
        if config.anomaly_detection_config:
            print("Anomaly Detection:")
            print(f"  Baseline Window: {config.anomaly_detection_config.baseline_window_hours} hours")
            print(f"  Z-Score Threshold: {config.anomaly_detection_config.z_score_threshold}")
            print(f"  Sensitivity: {config.anomaly_detection_config.sensitivity}")
            print(f"  Monitored Features: {', '.join(config.anomaly_detection_config.monitored_features)}")
            print()
        
        if config.incident_response_rules:
            print(f"Incident Response Rules ({len(config.incident_response_rules)}):")
            for rule in config.incident_response_rules:
                print(f"  - {rule.alert_category} ({rule.severity_threshold}): {', '.join(rule.actions)}")
                print(f"    Auto-execute: {rule.auto_execute}")
            print()
        
        if config.mfa_requirements:
            print("MFA Requirements:")
            for role, required in config.mfa_requirements.items():
                status = "Required" if required else "Not required"
                print(f"  - {role}: {status}")
            print()
        
        # Validate configuration
        is_valid, errors = parser.validate_config(config)
        if is_valid:
            print("✓ Configuration validation passed!")
        else:
            print("✗ Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
    
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        print("\nMake sure the example configuration file exists:")
        print("  config/security_config_example.yaml")
    
    except ValueError as e:
        print(f"✗ Configuration error: {e}")
    
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


if __name__ == "__main__":
    main()
