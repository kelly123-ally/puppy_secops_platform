"""
Round-trip test for SecurityConfigParser and SecurityConfigPrettyPrinter

Tests that configuration can be exported and re-imported without data loss.
This validates Requirement 23.1: Configuration round-trip preservation.
"""

import tempfile
import os
import pytest

from app.core.config_parser import SecurityConfigParser, SecurityConfig, TLSConfig
from app.core.config_printer import SecurityConfigPrettyPrinter
from app.core.key_manager import KeyRotationPolicy
from app.core.access_controller import RateLimitPolicy
from app.core.anomaly_detector import AnomalyDetectionConfig
from app.core.incident_response import ResponseRule


class TestConfigRoundTrip:
    """Test configuration round-trip (parse -> print -> parse)."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = SecurityConfigParser()
        self.printer = SecurityConfigPrettyPrinter()
        
        # Create a complete test configuration
        # Use actual certificate files that exist in the project
        self.test_config = SecurityConfig(
            tls_config=TLSConfig(
                cert_path="ca_cert.pem",
                key_path="ca_key.pem",
                protocols=["TLSv1.2", "TLSv1.3"],
                cipher_suites=["TLS_AES_256_GCM_SHA384"]
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
                monitored_features=["battery_level", "task_completion_time"]
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
                "robot": False
            }
        )
    
    def test_round_trip_preserves_tls_config(self):
        """Test that TLS configuration survives round-trip."""
        # Export configuration (without masking)
        yaml_output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_output)
            temp_path = f.name
        
        try:
            # Parse back
            parsed_config = self.parser.parse_config(temp_path)
            
            # Verify TLS config
            assert parsed_config.tls_config is not None
            assert parsed_config.tls_config.cert_path == self.test_config.tls_config.cert_path
            assert parsed_config.tls_config.key_path == self.test_config.tls_config.key_path
            assert parsed_config.tls_config.protocols == self.test_config.tls_config.protocols
            assert parsed_config.tls_config.cipher_suites == self.test_config.tls_config.cipher_suites
        finally:
            os.unlink(temp_path)
    
    def test_round_trip_preserves_key_rotation_policy(self):
        """Test that key rotation policy survives round-trip."""
        yaml_output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_output)
            temp_path = f.name
        
        try:
            parsed_config = self.parser.parse_config(temp_path)
            
            # Verify key rotation policy
            assert parsed_config.key_rotation_policy is not None
            assert parsed_config.key_rotation_policy.rotation_interval_hours == \
                   self.test_config.key_rotation_policy.rotation_interval_hours
            assert parsed_config.key_rotation_policy.grace_period_minutes == \
                   self.test_config.key_rotation_policy.grace_period_minutes
            assert parsed_config.key_rotation_policy.auto_rotate_master_key == \
                   self.test_config.key_rotation_policy.auto_rotate_master_key
        finally:
            os.unlink(temp_path)
    
    def test_round_trip_preserves_rate_limit_policies(self):
        """Test that rate limit policies survive round-trip."""
        yaml_output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_output)
            temp_path = f.name
        
        try:
            parsed_config = self.parser.parse_config(temp_path)
            
            # Verify rate limit policies
            assert len(parsed_config.rate_limit_policies) == len(self.test_config.rate_limit_policies)
            
            for original, parsed in zip(self.test_config.rate_limit_policies, 
                                       parsed_config.rate_limit_policies):
                assert parsed.endpoint_pattern == original.endpoint_pattern
                assert parsed.requests_per_window == original.requests_per_window
                assert parsed.window_seconds == original.window_seconds
                assert parsed.role_overrides == original.role_overrides
        finally:
            os.unlink(temp_path)
    
    def test_round_trip_preserves_anomaly_detection_config(self):
        """Test that anomaly detection config survives round-trip."""
        yaml_output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_output)
            temp_path = f.name
        
        try:
            parsed_config = self.parser.parse_config(temp_path)
            
            # Verify anomaly detection config
            assert parsed_config.anomaly_detection_config is not None
            assert parsed_config.anomaly_detection_config.baseline_window_hours == \
                   self.test_config.anomaly_detection_config.baseline_window_hours
            assert parsed_config.anomaly_detection_config.z_score_threshold == \
                   self.test_config.anomaly_detection_config.z_score_threshold
            assert parsed_config.anomaly_detection_config.sensitivity == \
                   self.test_config.anomaly_detection_config.sensitivity
            assert parsed_config.anomaly_detection_config.monitored_features == \
                   self.test_config.anomaly_detection_config.monitored_features
        finally:
            os.unlink(temp_path)
    
    def test_round_trip_preserves_incident_response_rules(self):
        """Test that incident response rules survive round-trip."""
        yaml_output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_output)
            temp_path = f.name
        
        try:
            parsed_config = self.parser.parse_config(temp_path)
            
            # Verify incident response rules
            assert len(parsed_config.incident_response_rules) == \
                   len(self.test_config.incident_response_rules)
            
            for original, parsed in zip(self.test_config.incident_response_rules,
                                       parsed_config.incident_response_rules):
                assert parsed.alert_category == original.alert_category
                assert parsed.severity_threshold == original.severity_threshold
                assert parsed.actions == original.actions
                assert parsed.auto_execute == original.auto_execute
        finally:
            os.unlink(temp_path)
    
    def test_round_trip_preserves_mfa_requirements(self):
        """Test that MFA requirements survive round-trip."""
        yaml_output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_output)
            temp_path = f.name
        
        try:
            parsed_config = self.parser.parse_config(temp_path)
            
            # Verify MFA requirements
            assert parsed_config.mfa_requirements == self.test_config.mfa_requirements
        finally:
            os.unlink(temp_path)
    
    def test_complete_round_trip(self):
        """Test that complete configuration survives round-trip.
        
        Validates Requirement 23.1: Configuration round-trip preservation
        """
        # Export configuration (without masking)
        yaml_output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_output)
            temp_path = f.name
        
        try:
            # Parse back
            parsed_config = self.parser.parse_config(temp_path)
            
            # Validate parsed config
            is_valid, errors = self.parser.validate_config(parsed_config)
            assert is_valid, f"Parsed config is invalid: {errors}"
            
            # Export again
            yaml_output_2 = self.printer.format_config(parsed_config, mask_secrets=False)
            
            # Parse again
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f2:
                f2.write(yaml_output_2)
                temp_path_2 = f2.name
            
            try:
                parsed_config_2 = self.parser.parse_config(temp_path_2)
                
                # Verify all sections match
                assert parsed_config_2.tls_config.cert_path == self.test_config.tls_config.cert_path
                assert parsed_config_2.key_rotation_policy.rotation_interval_hours == \
                       self.test_config.key_rotation_policy.rotation_interval_hours
                assert len(parsed_config_2.rate_limit_policies) == \
                       len(self.test_config.rate_limit_policies)
                assert parsed_config_2.anomaly_detection_config.sensitivity == \
                       self.test_config.anomaly_detection_config.sensitivity
                assert len(parsed_config_2.incident_response_rules) == \
                       len(self.test_config.incident_response_rules)
                assert parsed_config_2.mfa_requirements == self.test_config.mfa_requirements
            finally:
                os.unlink(temp_path_2)
        finally:
            os.unlink(temp_path)
    
    def test_partial_export_round_trip(self):
        """Test that partial exports can be parsed back."""
        # Export TLS section only
        tls_yaml = self.printer.export_partial_config(
            self.test_config, 
            "tls", 
            mask_secrets=False
        )
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(tls_yaml)
            temp_path = f.name
        
        try:
            # Parse back
            parsed_config = self.parser.parse_config(temp_path)
            
            # Should have TLS config
            assert parsed_config.tls_config is not None
            assert parsed_config.tls_config.cert_path == self.test_config.tls_config.cert_path
            
            # Other sections should be None or empty
            assert parsed_config.key_rotation_policy is None
            assert len(parsed_config.rate_limit_policies) == 0
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
