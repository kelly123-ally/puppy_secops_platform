"""
Example usage of SecurityConfigPrettyPrinter

Demonstrates:
- Formatting complete security configuration
- Exporting partial configuration sections
- Masking sensitive values
"""

from app.core.config_printer import SecurityConfigPrettyPrinter
from app.core.config_parser import SecurityConfig, TLSConfig
from app.core.key_manager import KeyRotationPolicy
from app.core.access_controller import RateLimitPolicy
from app.core.anomaly_detector import AnomalyDetectionConfig
from app.core.incident_response import ResponseRule


def main():
    """Demonstrate SecurityConfigPrettyPrinter usage."""
    
    # Create a sample security configuration
    config = SecurityConfig(
        tls_config=TLSConfig(
            cert_path="/etc/puppysecops/certs/server.crt",
            key_path="/etc/puppysecops/certs/server.key",
            protocols=["TLSv1.2", "TLSv1.3"],
            cipher_suites=[
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256"
            ]
        ),
        key_rotation_policy=KeyRotationPolicy(
            rotation_interval_hours=24,
            grace_period_minutes=5,
            auto_rotate_master_key=False
        ),
        rate_limit_policies=[
            RateLimitPolicy(
                endpoint_pattern="/api/tasks/*",
                requests_per_window=100,
                window_seconds=60,
                role_overrides={"admin": 200, "operator": 150}
            ),
            RateLimitPolicy(
                endpoint_pattern="/api/robots/*",
                requests_per_window=50,
                window_seconds=60,
                role_overrides={"admin": 100}
            )
        ],
        anomaly_detection_config=AnomalyDetectionConfig(
            baseline_window_hours=24,
            z_score_threshold=3.0,
            sensitivity="medium",
            monitored_features=[
                "battery_level",
                "task_completion_time",
                "message_frequency",
                "movement_speed"
            ]
        ),
        incident_response_rules=[
            ResponseRule(
                alert_category="anomaly",
                severity_threshold="critical",
                actions=["revoke_cert", "block_client"],
                auto_execute=True
            ),
            ResponseRule(
                alert_category="auth_failure",
                severity_threshold="high",
                actions=["block_client"],
                auto_execute=True
            )
        ],
        mfa_requirements={
            "admin": True,
            "operator": True,
            "robot": False,
            "guest": False
        }
    )
    
    # Create pretty printer
    printer = SecurityConfigPrettyPrinter()
    
    print("=" * 80)
    print("Example 1: Format complete configuration with masked secrets")
    print("=" * 80)
    print()
    
    # Format complete configuration with masked secrets
    output = printer.format_config(config, mask_secrets=True)
    print(output)
    
    print()
    print("=" * 80)
    print("Example 2: Format complete configuration without masking")
    print("=" * 80)
    print()
    
    # Format complete configuration without masking
    output = printer.format_config(config, mask_secrets=False)
    print(output)
    
    print()
    print("=" * 80)
    print("Example 3: Export only TLS configuration")
    print("=" * 80)
    print()
    
    # Export partial configuration - TLS only
    tls_output = printer.export_partial_config(config, "tls", mask_secrets=False)
    print(tls_output)
    
    print()
    print("=" * 80)
    print("Example 4: Export only rate limiting policies")
    print("=" * 80)
    print()
    
    # Export partial configuration - rate limits only
    rate_limit_output = printer.export_partial_config(config, "rate_limits")
    print(rate_limit_output)
    
    print()
    print("=" * 80)
    print("Example 5: Export only anomaly detection configuration")
    print("=" * 80)
    print()
    
    # Export partial configuration - anomaly detection only
    anomaly_output = printer.export_partial_config(config, "anomaly_detection")
    print(anomaly_output)
    
    print()
    print("=" * 80)
    print("Example 6: Export only MFA requirements")
    print("=" * 80)
    print()
    
    # Export partial configuration - MFA only
    mfa_output = printer.export_partial_config(config, "mfa")
    print(mfa_output)


if __name__ == "__main__":
    main()
