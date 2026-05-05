"""
Unit tests for SecurityConfigPrettyPrinter

Tests configuration formatting, comment generation, sensitive value masking,
and partial configuration export.

Validates Requirements: 22.1-22.5
"""

import pytest
import yaml

from app.core.config_printer import SecurityConfigPrettyPrinter
from app.core.config_parser import SecurityConfig, TLSConfig
from app.core.key_manager import KeyRotationPolicy
from app.core.access_controller import RateLimitPolicy
from app.core.anomaly_detector import AnomalyDetectionConfig
from app.core.incident_response import ResponseRule


class TestSecurityConfigPrettyPrinter:
    """Test suite for SecurityConfigPrettyPrinter."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.printer = SecurityConfigPrettyPrinter()
        
        # Create a complete test configuration
        self.test_config = SecurityConfig(
            tls_config=TLSConfig(
                cert_path="/path/to/cert.pem",
                key_path="/path/to/key.pem",
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
    
    def test_format_config_produces_valid_yaml(self):
        """Test that formatted output is valid YAML.
        
        Validates Requirement 22.1: Format configuration objects into valid YAML
        """
        output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Remove comment lines for YAML parsing
        yaml_lines = [line for line in output.split('\n') if not line.strip().startswith('#')]
        yaml_content = '\n'.join(yaml_lines)
        
        # Should parse without errors
        parsed = yaml.safe_load(yaml_content)
        assert parsed is not None
        assert isinstance(parsed, dict)
    
    def test_format_config_includes_comments(self):
        """Test that formatted output includes explanatory comments.
        
        Validates Requirement 22.2: Include comments explaining each parameter
        """
        output = self.printer.format_config(self.test_config)
        
        # Check for section header comments
        assert "# TLS/SSL Configuration" in output
        assert "# Key Rotation Policy" in output
        assert "# API Rate Limiting Policies" in output
        assert "# Anomaly Detection Configuration" in output
        assert "# Incident Response Rules" in output
        assert "# Multi-Factor Authentication Requirements" in output
        
        # Check for parameter explanation comments
        assert "# Path to TLS certificate file" in output
        assert "# Hours between automatic key rotations" in output
        assert "# Maximum requests allowed per time window" in output
        assert "# Z-score threshold for anomaly detection" in output
    
    def test_format_config_masks_sensitive_values(self):
        """Test that sensitive values are masked by default.
        
        Validates Requirement 22.3: Mask sensitive values in output
        """
        output = self.printer.format_config(self.test_config, mask_secrets=True)
        
        # Sensitive paths should be masked
        assert "***MASKED***" in output
        assert "/path/to/cert.pem" not in output
        assert "/path/to/key.pem" not in output
    
    def test_format_config_preserves_sensitive_values_when_not_masked(self):
        """Test that sensitive values are preserved when masking is disabled."""
        output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Sensitive paths should be visible
        assert "/path/to/cert.pem" in output
        assert "/path/to/key.pem" in output
        assert "***MASKED***" not in output
    
    def test_format_config_maintains_consistent_indentation(self):
        """Test that output maintains consistent YAML indentation.
        
        Validates Requirement 22.4: Maintain consistent formatting and indentation
        """
        output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        lines = output.split('\n')
        
        # Check that nested structures use consistent 2-space indentation
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith('#'):
                # Count leading spaces
                leading_spaces = len(line) - len(line.lstrip())
                # Should be a multiple of 2
                assert leading_spaces % 2 == 0, f"Line {i+1} has inconsistent indentation: {line}"
    
    def test_format_config_with_empty_config(self):
        """Test formatting an empty configuration."""
        empty_config = SecurityConfig()
        output = self.printer.format_config(empty_config)
        
        # Should still have header
        assert "# Security Configuration" in output
        
        # Should not crash
        assert isinstance(output, str)
    
    def test_export_partial_config_tls(self):
        """Test exporting only TLS configuration section.
        
        Validates Requirement 22.5: Support exporting partial configuration sections
        """
        output = self.printer.export_partial_config(
            self.test_config, 
            "tls", 
            mask_secrets=False
        )
        
        # Should contain TLS section
        assert "tls:" in output
        assert "cert_path:" in output
        assert "key_path:" in output
        assert "protocols:" in output
        
        # Should not contain other sections
        assert "key_rotation:" not in output
        assert "rate_limits:" not in output
        assert "anomaly_detection:" not in output
    
    def test_export_partial_config_key_rotation(self):
        """Test exporting only key rotation policy section."""
        output = self.printer.export_partial_config(
            self.test_config, 
            "key_rotation"
        )
        
        # Should contain key rotation section
        assert "key_rotation:" in output
        assert "rotation_interval_hours:" in output
        assert "grace_period_minutes:" in output
        assert "auto_rotate_master_key:" in output
        
        # Should not contain other sections
        assert "tls:" not in output
        assert "rate_limits:" not in output
    
    def test_export_partial_config_rate_limits(self):
        """Test exporting only rate limit policies section."""
        output = self.printer.export_partial_config(
            self.test_config, 
            "rate_limits"
        )
        
        # Should contain rate limits section
        assert "rate_limits:" in output
        assert "endpoint_pattern:" in output
        assert "requests_per_window:" in output
        assert "window_seconds:" in output
        assert "role_overrides:" in output
        
        # Should not contain other sections
        assert "tls:" not in output
        assert "key_rotation:" not in output
    
    def test_export_partial_config_anomaly_detection(self):
        """Test exporting only anomaly detection configuration section."""
        output = self.printer.export_partial_config(
            self.test_config, 
            "anomaly_detection"
        )
        
        # Should contain anomaly detection section
        assert "anomaly_detection:" in output
        assert "baseline_window_hours:" in output
        assert "z_score_threshold:" in output
        assert "sensitivity:" in output
        assert "monitored_features:" in output
        
        # Should not contain other sections
        assert "tls:" not in output
        assert "incident_response:" not in output
    
    def test_export_partial_config_incident_response(self):
        """Test exporting only incident response rules section."""
        output = self.printer.export_partial_config(
            self.test_config, 
            "incident_response"
        )
        
        # Should contain incident response section
        assert "incident_response:" in output
        assert "alert_category:" in output
        assert "severity_threshold:" in output
        assert "actions:" in output
        assert "auto_execute:" in output
        
        # Should not contain other sections
        assert "tls:" not in output
        assert "mfa_requirements:" not in output
    
    def test_export_partial_config_mfa(self):
        """Test exporting only MFA requirements section."""
        output = self.printer.export_partial_config(
            self.test_config, 
            "mfa"
        )
        
        # Should contain MFA section
        assert "mfa_requirements:" in output
        assert "admin:" in output
        assert "operator:" in output
        assert "robot:" in output
        
        # Should not contain other sections
        assert "tls:" not in output
        assert "key_rotation:" not in output
    
    def test_export_partial_config_invalid_section(self):
        """Test that exporting invalid section raises ValueError."""
        with pytest.raises(ValueError, match="Invalid section"):
            self.printer.export_partial_config(self.test_config, "invalid_section")
    
    def test_export_partial_config_missing_section(self):
        """Test that exporting unconfigured section raises ValueError."""
        empty_config = SecurityConfig()
        
        with pytest.raises(ValueError, match="TLS configuration is not set"):
            self.printer.export_partial_config(empty_config, "tls")
        
        with pytest.raises(ValueError, match="Key rotation policy is not set"):
            self.printer.export_partial_config(empty_config, "key_rotation")
    
    def test_format_tls_config_with_cipher_suites(self):
        """Test formatting TLS config with cipher suites."""
        output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Should include cipher suites
        assert "cipher_suites:" in output
        assert "TLS_AES_256_GCM_SHA384" in output
    
    def test_format_tls_config_without_cipher_suites(self):
        """Test formatting TLS config without cipher suites."""
        config = SecurityConfig(
            tls_config=TLSConfig(
                cert_path="/path/to/cert.pem",
                key_path="/path/to/key.pem",
                protocols=["TLSv1.3"]
            )
        )
        
        output = self.printer.format_config(config, mask_secrets=False)
        
        # Should not include cipher suites section
        assert "cipher_suites:" not in output
    
    def test_format_rate_limit_policies_multiple(self):
        """Test formatting multiple rate limit policies."""
        output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Should include both policies
        assert "/api/tasks/*" in output
        assert "/api/robots/*" in output
        
        # Should include role overrides
        assert "admin: 200" in output
        assert "operator: 150" in output
        assert "admin: 100" in output
    
    def test_format_incident_response_rules_multiple(self):
        """Test formatting multiple incident response rules."""
        output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Should include both rules
        assert "anomaly" in output
        assert "auth_failure" in output
        
        # Should include actions
        assert "revoke_cert" in output
        assert "block_client" in output
    
    def test_format_mfa_requirements_sorted(self):
        """Test that MFA requirements are sorted alphabetically."""
        output = self.printer.format_config(self.test_config)
        
        lines = output.split('\n')
        mfa_section_start = None
        
        # Find MFA section
        for i, line in enumerate(lines):
            if line.strip() == "mfa_requirements:":
                mfa_section_start = i
                break
        
        assert mfa_section_start is not None
        
        # Extract role names in order
        roles = []
        for line in lines[mfa_section_start + 1:]:
            if line.strip() and not line.strip().startswith('#'):
                if ':' in line:
                    role = line.split(':')[0].strip()
                    roles.append(role)
                else:
                    break
        
        # Should be sorted
        assert roles == sorted(roles)
    
    def test_is_sensitive_field(self):
        """Test sensitive field detection."""
        # Sensitive fields
        assert self.printer._is_sensitive_field("cert_path")
        assert self.printer._is_sensitive_field("key_path")
        assert self.printer._is_sensitive_field("password")
        assert self.printer._is_sensitive_field("secret_key")
        assert self.printer._is_sensitive_field("private_key")
        assert self.printer._is_sensitive_field("signing_key_path")
        
        # Non-sensitive fields
        assert not self.printer._is_sensitive_field("rotation_interval_hours")
        assert not self.printer._is_sensitive_field("endpoint_pattern")
        assert not self.printer._is_sensitive_field("sensitivity")
    
    def test_mask_value(self):
        """Test value masking."""
        # With masking enabled
        assert self.printer._mask_value("/path/to/secret", mask=True) == "***MASKED***"
        
        # With masking disabled
        assert self.printer._mask_value("/path/to/secret", mask=False) == "/path/to/secret"
    
    def test_format_config_all_sections_present(self):
        """Test that all configured sections appear in output."""
        output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Parse YAML (excluding comments)
        yaml_lines = [line for line in output.split('\n') if not line.strip().startswith('#')]
        yaml_content = '\n'.join(yaml_lines)
        parsed = yaml.safe_load(yaml_content)
        
        # All sections should be present
        assert "tls" in parsed
        assert "key_rotation" in parsed
        assert "rate_limits" in parsed
        assert "anomaly_detection" in parsed
        assert "incident_response" in parsed
        assert "mfa_requirements" in parsed
    
    def test_format_config_preserves_data_types(self):
        """Test that data types are preserved in YAML output."""
        output = self.printer.format_config(self.test_config, mask_secrets=False)
        
        # Parse YAML
        yaml_lines = [line for line in output.split('\n') if not line.strip().startswith('#')]
        yaml_content = '\n'.join(yaml_lines)
        parsed = yaml.safe_load(yaml_content)
        
        # Check data types
        assert isinstance(parsed["key_rotation"]["rotation_interval_hours"], int)
        assert isinstance(parsed["key_rotation"]["auto_rotate_master_key"], bool)
        assert isinstance(parsed["anomaly_detection"]["z_score_threshold"], float)
        assert isinstance(parsed["rate_limits"], list)
        assert isinstance(parsed["mfa_requirements"], dict)
    
    def test_format_config_case_insensitive_section_names(self):
        """Test that partial export handles case-insensitive section names."""
        # Should work with different cases
        output1 = self.printer.export_partial_config(self.test_config, "TLS", mask_secrets=False)
        output2 = self.printer.export_partial_config(self.test_config, "tls", mask_secrets=False)
        output3 = self.printer.export_partial_config(self.test_config, "Tls", mask_secrets=False)
        
        # All should produce similar output (ignoring header comments)
        assert "tls:" in output1
        assert "tls:" in output2
        assert "tls:" in output3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
