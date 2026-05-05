"""
Unit tests for SecurityConfigParser

Tests configuration parsing, validation, and error handling.
"""

import pytest
import tempfile
from pathlib import Path

from app.core.config_parser import (
    SecurityConfigParser,
    SecurityConfig,
    TLSConfig,
)
from app.core.key_manager import KeyRotationPolicy
from app.core.access_controller import RateLimitPolicy
from app.core.anomaly_detector import AnomalyDetectionConfig
from app.core.incident_response import ResponseRule


class TestSecurityConfigParser:
    """Test suite for SecurityConfigParser."""
    
    @pytest.fixture
    def parser(self):
        """Create a SecurityConfigParser instance."""
        return SecurityConfigParser()
    
    @pytest.fixture
    def temp_cert_files(self):
        """Create temporary certificate files for testing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_file.write("FAKE CERT")
            cert_path = cert_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as key_file:
            key_file.write("FAKE KEY")
            key_path = key_file.name
        
        yield cert_path, key_path
        
        # Cleanup
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)
    
    def test_parse_empty_config(self, parser):
        """Test parsing an empty configuration file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Configuration file is empty"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_nonexistent_file(self, parser):
        """Test parsing a nonexistent configuration file."""
        with pytest.raises(FileNotFoundError, match="Configuration file not found"):
            parser.parse_config("/nonexistent/config.yaml")
    
    def test_parse_invalid_yaml_syntax(self, parser):
        """Test parsing a file with invalid YAML syntax."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: syntax: [")
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Invalid YAML syntax"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_non_dict_config(self, parser):
        """Test parsing a configuration that is not a dictionary."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("- item1\n- item2")
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Configuration must be a YAML dictionary"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_minimal_valid_config(self, parser):
        """Test parsing a minimal valid configuration."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("{}")
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            assert isinstance(config, SecurityConfig)
            assert config.tls_config is None
            assert config.key_rotation_policy is None
            assert config.rate_limit_policies == []
            assert config.anomaly_detection_config is None
            assert config.incident_response_rules == []
            assert config.mfa_requirements == {}
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_tls_config(self, parser, temp_cert_files):
        """Test parsing TLS configuration section."""
        cert_path, key_path = temp_cert_files
        
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
  protocols:
    - TLSv1.2
    - TLSv1.3
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            assert config.tls_config is not None
            assert config.tls_config.cert_path == cert_path
            assert config.tls_config.key_path == key_path
            assert config.tls_config.protocols == ["TLSv1.2", "TLSv1.3"]
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_tls_config_missing_cert_path(self, parser):
        """Test parsing TLS config with missing cert_path."""
        yaml_content = """
tls:
  key_path: /path/to/key.pem
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="TLS config requires both"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_key_rotation_policy(self, parser):
        """Test parsing key rotation policy section."""
        yaml_content = """
key_rotation:
  rotation_interval_hours: 48
  grace_period_minutes: 10
  auto_rotate_master_key: true
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            assert config.key_rotation_policy is not None
            assert config.key_rotation_policy.rotation_interval_hours == 48
            assert config.key_rotation_policy.grace_period_minutes == 10
            assert config.key_rotation_policy.auto_rotate_master_key is True
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_key_rotation_policy_invalid_interval(self, parser):
        """Test parsing key rotation policy with invalid interval."""
        yaml_content = """
key_rotation:
  rotation_interval_hours: 1000
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="rotation_interval_hours must be between"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_rate_limit_policies(self, parser):
        """Test parsing rate limit policies section."""
        yaml_content = """
rate_limits:
  - endpoint_pattern: "/api/tasks/*"
    requests_per_window: 100
    window_seconds: 60
    role_overrides:
      admin: 200
      operator: 150
  - endpoint_pattern: "/api/robots/*"
    requests_per_window: 50
    window_seconds: 60
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            assert len(config.rate_limit_policies) == 2
            
            policy1 = config.rate_limit_policies[0]
            assert policy1.endpoint_pattern == "/api/tasks/*"
            assert policy1.requests_per_window == 100
            assert policy1.window_seconds == 60
            assert policy1.role_overrides == {"admin": 200, "operator": 150}
            
            policy2 = config.rate_limit_policies[1]
            assert policy2.endpoint_pattern == "/api/robots/*"
            assert policy2.requests_per_window == 50
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_rate_limit_policy_missing_required_field(self, parser):
        """Test parsing rate limit policy with missing required field."""
        yaml_content = """
rate_limits:
  - endpoint_pattern: "/api/tasks/*"
    window_seconds: 60
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="requires 'requests_per_window'"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_anomaly_detection_config(self, parser):
        """Test parsing anomaly detection configuration section."""
        yaml_content = """
anomaly_detection:
  baseline_window_hours: 48
  z_score_threshold: 2.5
  sensitivity: high
  monitored_features:
    - battery_level
    - movement_speed
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            assert config.anomaly_detection_config is not None
            assert config.anomaly_detection_config.baseline_window_hours == 48
            assert config.anomaly_detection_config.z_score_threshold == 2.5
            assert config.anomaly_detection_config.sensitivity == "high"
            assert config.anomaly_detection_config.monitored_features == [
                "battery_level", "movement_speed"
            ]
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_incident_response_rules(self, parser):
        """Test parsing incident response rules section."""
        yaml_content = """
incident_response:
  - alert_category: anomaly
    severity_threshold: critical
    actions:
      - revoke_cert
      - block_client
    auto_execute: true
  - alert_category: auth_failure
    severity_threshold: high
    actions:
      - block_client
    auto_execute: false
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            assert len(config.incident_response_rules) == 2
            
            rule1 = config.incident_response_rules[0]
            assert rule1.alert_category == "anomaly"
            assert rule1.severity_threshold == "critical"
            assert rule1.actions == ["revoke_cert", "block_client"]
            assert rule1.auto_execute is True
            
            rule2 = config.incident_response_rules[1]
            assert rule2.alert_category == "auth_failure"
            assert rule2.severity_threshold == "high"
            assert rule2.actions == ["block_client"]
            assert rule2.auto_execute is False
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_incident_response_rule_missing_required_field(self, parser):
        """Test parsing incident response rule with missing required field."""
        yaml_content = """
incident_response:
  - alert_category: anomaly
    actions:
      - revoke_cert
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="requires 'severity_threshold'"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_mfa_requirements(self, parser):
        """Test parsing MFA requirements section."""
        yaml_content = """
mfa_requirements:
  admin: true
  operator: true
  robot: false
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            assert config.mfa_requirements == {
                "admin": True,
                "operator": True,
                "robot": False
            }
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_mfa_requirements_invalid_value(self, parser):
        """Test parsing MFA requirements with invalid value."""
        yaml_content = """
mfa_requirements:
  admin: "yes"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="must be boolean"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_parse_complete_config(self, parser, temp_cert_files):
        """Test parsing a complete configuration with all sections."""
        cert_path, key_path = temp_cert_files
        
        yaml_content = f"""
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

rate_limits:
  - endpoint_pattern: "/api/*"
    requests_per_window: 100
    window_seconds: 60

anomaly_detection:
  baseline_window_hours: 24
  z_score_threshold: 3.0
  sensitivity: medium
  monitored_features:
    - battery_level
    - task_completion_time

incident_response:
  - alert_category: anomaly
    severity_threshold: critical
    actions:
      - revoke_cert
    auto_execute: true

mfa_requirements:
  admin: true
  operator: false
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            
            # Verify all sections are parsed
            assert config.tls_config is not None
            assert config.key_rotation_policy is not None
            assert len(config.rate_limit_policies) == 1
            assert config.anomaly_detection_config is not None
            assert len(config.incident_response_rules) == 1
            assert len(config.mfa_requirements) == 2
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_validate_config_with_nonexistent_cert_files(self, parser):
        """Test validation fails when certificate files don't exist."""
        yaml_content = """
tls:
  cert_path: /nonexistent/cert.pem
  key_path: /nonexistent/key.pem
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="certificate file not found"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_validate_config_with_invalid_tls_protocol(self, parser, temp_cert_files):
        """Test validation fails with invalid TLS protocol."""
        cert_path, key_path = temp_cert_files
        
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
  protocols:
    - TLSv1.0
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Invalid TLS protocol"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_validate_config_with_negative_rate_limit(self, parser):
        """Test validation fails with negative rate limit."""
        yaml_content = """
rate_limits:
  - endpoint_pattern: "/api/*"
    requests_per_window: -10
    window_seconds: 60
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="requests_per_window must be positive"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_validate_config_with_invalid_sensitivity(self, parser):
        """Test validation fails with invalid anomaly detection sensitivity."""
        yaml_content = """
anomaly_detection:
  sensitivity: invalid
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="sensitivity must be one of"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_validate_config_with_invalid_severity_threshold(self, parser):
        """Test validation fails with invalid severity threshold."""
        yaml_content = """
incident_response:
  - alert_category: anomaly
    severity_threshold: invalid
    actions:
      - revoke_cert
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="severity_threshold must be one of"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_validate_config_with_invalid_action(self, parser):
        """Test validation fails with invalid incident response action."""
        yaml_content = """
incident_response:
  - alert_category: anomaly
    severity_threshold: critical
    actions:
      - invalid_action
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="invalid action"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_validate_config_with_empty_actions(self, parser):
        """Test validation fails with empty actions list."""
        yaml_content = """
incident_response:
  - alert_category: anomaly
    severity_threshold: critical
    actions: []
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="actions list cannot be empty"):
                parser.parse_config(config_path)
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_descriptive_error_messages(self, parser):
        """Test that error messages are descriptive (Requirement 21.4)."""
        yaml_content = """
rate_limits:
  - endpoint_pattern: "/api/*"
    requests_per_window: -10
    window_seconds: -5
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError) as exc_info:
                parser.parse_config(config_path)
            
            error_message = str(exc_info.value)
            # Should contain multiple descriptive errors
            assert "requests_per_window must be positive" in error_message
            assert "window_seconds must be positive" in error_message
        finally:
            Path(config_path).unlink(missing_ok=True)


class TestConfigurationHotReload:
    """Test suite for configuration hot-reload functionality."""
    
    @pytest.fixture
    def parser(self):
        """Create a SecurityConfigParser instance."""
        return SecurityConfigParser()
    
    @pytest.fixture
    def parser_with_audit_logger(self):
        """Create a SecurityConfigParser with a mock audit logger."""
        from unittest.mock import Mock
        audit_logger = Mock()
        return SecurityConfigParser(audit_logger=audit_logger), audit_logger
    
    @pytest.fixture
    def temp_cert_files(self):
        """Create temporary certificate files for testing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_file.write("FAKE CERT")
            cert_path = cert_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as key_file:
            key_file.write("FAKE KEY")
            key_path = key_file.name
        
        yield cert_path, key_path
        
        # Cleanup
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)
    
    def test_reload_config_without_initial_load(self, parser):
        """Test that reload_config raises error if no config loaded yet."""
        with pytest.raises(RuntimeError, match="no configuration file has been loaded yet"):
            parser.reload_config()
    
    def test_reload_config_success(self, parser, temp_cert_files):
        """Test successful configuration reload."""
        cert_path, key_path = temp_cert_files
        
        # Initial configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}

key_rotation:
  rotation_interval_hours: 24
  grace_period_minutes: 5
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            # Load initial config
            config1 = parser.parse_config(config_path)
            assert config1.key_rotation_policy.rotation_interval_hours == 24
            
            # Modify the config file
            yaml_content_updated = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}

key_rotation:
  rotation_interval_hours: 48
  grace_period_minutes: 10
"""
            with open(config_path, 'w') as f:
                f.write(yaml_content_updated)
            
            # Reload configuration
            success, error = parser.reload_config()
            
            assert success is True
            assert error is None
            
            # Verify new config is loaded
            current_config = parser.get_current_config()
            assert current_config is not None
            assert current_config.key_rotation_policy.rotation_interval_hours == 48
            assert current_config.key_rotation_policy.grace_period_minutes == 10
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_reload_config_with_invalid_config(self, parser, temp_cert_files):
        """Test reload_config handles invalid configuration gracefully."""
        cert_path, key_path = temp_cert_files
        
        # Initial valid configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            # Load initial config
            config1 = parser.parse_config(config_path)
            assert config1.tls_config is not None
            
            # Modify the config file with invalid content
            yaml_content_invalid = """
rate_limits:
  - endpoint_pattern: "/api/*"
    requests_per_window: -10
    window_seconds: 60
"""
            with open(config_path, 'w') as f:
                f.write(yaml_content_invalid)
            
            # Reload configuration should fail
            success, error = parser.reload_config()
            
            assert success is False
            assert error is not None
            assert "Configuration reload failed" in error
            
            # Verify old config is still active
            current_config = parser.get_current_config()
            assert current_config is not None
            assert current_config.tls_config is not None
            assert current_config.tls_config.cert_path == cert_path
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_reload_config_logs_to_audit_logger(self, parser_with_audit_logger, temp_cert_files):
        """Test that configuration reload is logged to audit logger (Requirement 21.6)."""
        parser, audit_logger = parser_with_audit_logger
        cert_path, key_path = temp_cert_files
        
        # Initial configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}

mfa_requirements:
  admin: true
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            # Load initial config
            parser.parse_config(config_path)
            
            # Modify the config file
            yaml_content_updated = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}

mfa_requirements:
  admin: true
  operator: true
"""
            with open(config_path, 'w') as f:
                f.write(yaml_content_updated)
            
            # Reload configuration
            success, error = parser.reload_config()
            
            assert success is True
            
            # Verify audit logger was called
            assert audit_logger.log_event.called
            call_args = audit_logger.log_event.call_args
            
            assert call_args[1]['category'] == 'configuration'
            assert call_args[1]['title'] == 'Configuration reloaded'
            assert call_args[1]['actor'] == 'system'
            assert 'changes' in call_args[1]['details']
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_reload_config_logs_failure_to_audit_logger(self, parser_with_audit_logger, temp_cert_files):
        """Test that configuration reload failures are logged to audit logger."""
        parser, audit_logger = parser_with_audit_logger
        cert_path, key_path = temp_cert_files
        
        # Initial configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            # Load initial config
            parser.parse_config(config_path)
            
            # Modify the config file with invalid content
            with open(config_path, 'w') as f:
                f.write("invalid: yaml: syntax: [")
            
            # Reload configuration should fail
            success, error = parser.reload_config()
            
            assert success is False
            
            # Verify audit logger was called with failure
            assert audit_logger.log_event.called
            call_args = audit_logger.log_event.call_args
            
            assert call_args[1]['category'] == 'configuration'
            assert call_args[1]['title'] == 'Configuration reload failed'
            assert call_args[1]['actor'] == 'system'
            assert 'error' in call_args[1]['details']
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_reload_config_detects_changes(self, parser, temp_cert_files):
        """Test that reload_config correctly detects configuration changes."""
        cert_path, key_path = temp_cert_files
        
        # Initial configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}

key_rotation:
  rotation_interval_hours: 24

mfa_requirements:
  admin: true
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            # Load initial config
            parser.parse_config(config_path)
            
            # Modify multiple sections
            yaml_content_updated = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}

key_rotation:
  rotation_interval_hours: 48

mfa_requirements:
  admin: true
  operator: false

rate_limits:
  - endpoint_pattern: "/api/*"
    requests_per_window: 100
    window_seconds: 60
"""
            with open(config_path, 'w') as f:
                f.write(yaml_content_updated)
            
            # Reload configuration
            success, error = parser.reload_config()
            
            assert success is True
            
            # Verify changes are detected
            current_config = parser.get_current_config()
            assert current_config.key_rotation_policy.rotation_interval_hours == 48
            assert current_config.mfa_requirements == {"admin": True, "operator": False}
            assert len(current_config.rate_limit_policies) == 1
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_reload_config_with_no_changes(self, parser_with_audit_logger, temp_cert_files):
        """Test reload_config when configuration hasn't changed."""
        parser, audit_logger = parser_with_audit_logger
        cert_path, key_path = temp_cert_files
        
        # Initial configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            # Load initial config
            parser.parse_config(config_path)
            
            # Reload without changes
            success, error = parser.reload_config()
            
            assert success is True
            
            # Verify audit logger was called
            assert audit_logger.log_event.called
            call_args = audit_logger.log_event.call_args
            
            # Should log reload even with no changes
            assert call_args[1]['category'] == 'configuration'
            assert call_args[1]['title'] == 'Configuration reloaded'
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_config_change_callbacks(self, parser, temp_cert_files):
        """Test that registered callbacks are invoked on config reload."""
        cert_path, key_path = temp_cert_files
        
        # Track callback invocations
        callback_invoked = []
        
        def config_callback(new_config: SecurityConfig):
            callback_invoked.append(new_config)
        
        parser.register_config_change_callback(config_callback)
        
        # Initial configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            # Load initial config
            parser.parse_config(config_path)
            
            # Reload configuration
            success, error = parser.reload_config()
            
            assert success is True
            assert len(callback_invoked) == 1
            assert callback_invoked[0].tls_config is not None
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_config_change_callback_error_handling(self, parser_with_audit_logger, temp_cert_files):
        """Test that callback errors don't prevent reload from succeeding."""
        parser, audit_logger = parser_with_audit_logger
        cert_path, key_path = temp_cert_files
        
        # Register a callback that raises an error
        def failing_callback(new_config: SecurityConfig):
            raise ValueError("Callback error")
        
        parser.register_config_change_callback(failing_callback)
        
        # Initial configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            # Load initial config
            parser.parse_config(config_path)
            
            # Reload configuration should succeed despite callback error
            success, error = parser.reload_config()
            
            assert success is True
            
            # Verify callback error was logged
            # Check if any call to log_event mentions callback error
            callback_error_logged = False
            for call in audit_logger.log_event.call_args_list:
                if 'callback error' in call[1]['title'].lower():
                    callback_error_logged = True
                    break
            
            assert callback_error_logged
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_get_current_config(self, parser, temp_cert_files):
        """Test get_current_config returns the loaded configuration."""
        cert_path, key_path = temp_cert_files
        
        # Before loading any config
        assert parser.get_current_config() is None
        
        # Load configuration
        yaml_content = f"""
tls:
  cert_path: {cert_path}
  key_path: {key_path}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            config_path = f.name
        
        try:
            config = parser.parse_config(config_path)
            
            # After loading
            current_config = parser.get_current_config()
            assert current_config is not None
            assert current_config.tls_config is not None
            assert current_config.tls_config.cert_path == cert_path
            
        finally:
            Path(config_path).unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
