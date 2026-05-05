"""
Security Configuration Pretty Printer for PuppySecOps Platform

Provides configuration export including:
- Format SecurityConfig objects as valid YAML
- Include comments explaining each parameter
- Mask sensitive values (keys, passwords) in output
- Maintain consistent formatting and indentation
- Support exporting partial configuration sections

Requirements: 22.1-22.5
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    raise ImportError(
        "pyyaml is required for configuration printing. "
        "Install it with: pip install pyyaml"
    )

from app.core.config_parser import SecurityConfig, TLSConfig
from app.core.key_manager import KeyRotationPolicy
from app.core.access_controller import RateLimitPolicy
from app.core.anomaly_detector import AnomalyDetectionConfig
from app.core.incident_response import ResponseRule


class SecurityConfigPrettyPrinter:
    """Formats security configuration objects into human-readable YAML.
    
    Validates Requirements:
    - 22.1: Format security configuration objects into valid YAML
    - 22.2: Include comments explaining each parameter
    - 22.3: Mask sensitive values (keys, passwords) in output
    - 22.4: Maintain consistent formatting and indentation
    - 22.5: Support exporting partial configuration sections
    """
    
    # Sensitive field patterns to mask
    SENSITIVE_PATTERNS = [
        'key', 'password', 'secret', 'token', 'credential',
        'cert_path', 'key_path', 'private', 'signing_key'
    ]
    
    def __init__(self):
        """Initialize SecurityConfigPrettyPrinter."""
        pass
    
    def format_config(
        self, 
        config: SecurityConfig, 
        mask_secrets: bool = True
    ) -> str:
        """Format complete security configuration as YAML with comments.
        
        Validates Requirements:
        - 22.1: Format configuration objects into valid YAML
        - 22.2: Include comments explaining each parameter
        - 22.3: Mask sensitive values when mask_secrets=True
        - 22.4: Maintain consistent formatting and indentation
        
        Args:
            config: SecurityConfig object to format
            mask_secrets: Whether to mask sensitive values (default: True)
            
        Returns:
            YAML-formatted configuration string with comments
        """
        lines = []
        
        # Header comment
        lines.append("# Security Configuration for PuppySecOps Platform")
        lines.append("#")
        lines.append("# This configuration was exported from the running system.")
        lines.append("# Sensitive values have been masked for security.")
        lines.append("")
        
        # TLS Configuration
        if config.tls_config:
            lines.extend(self._format_tls_config(config.tls_config, mask_secrets))
            lines.append("")
        
        # Key Rotation Policy
        if config.key_rotation_policy:
            lines.extend(self._format_key_rotation_policy(config.key_rotation_policy))
            lines.append("")
        
        # Rate Limit Policies
        if config.rate_limit_policies:
            lines.extend(self._format_rate_limit_policies(config.rate_limit_policies))
            lines.append("")
        
        # Anomaly Detection Configuration
        if config.anomaly_detection_config:
            lines.extend(self._format_anomaly_detection_config(config.anomaly_detection_config))
            lines.append("")
        
        # Incident Response Rules
        if config.incident_response_rules:
            lines.extend(self._format_incident_response_rules(config.incident_response_rules))
            lines.append("")
        
        # MFA Requirements
        if config.mfa_requirements:
            lines.extend(self._format_mfa_requirements(config.mfa_requirements))
            lines.append("")
        
        return "\n".join(lines)
    
    def export_partial_config(
        self, 
        config: SecurityConfig, 
        section: str,
        mask_secrets: bool = True
    ) -> str:
        """Export specific configuration section.
        
        Validates Requirement 22.5: Support exporting partial configuration sections
        
        Args:
            config: SecurityConfig object
            section: Section name (tls, key_rotation, rate_limits, anomaly_detection, 
                    incident_response, mfa)
            mask_secrets: Whether to mask sensitive values (default: True)
            
        Returns:
            YAML-formatted section string with comments
            
        Raises:
            ValueError: If section name is invalid or section is not configured
        """
        section = section.lower()
        
        lines = []
        lines.append(f"# Security Configuration - {section.replace('_', ' ').title()} Section")
        lines.append("")
        
        if section == "tls":
            if not config.tls_config:
                raise ValueError("TLS configuration is not set")
            lines.extend(self._format_tls_config(config.tls_config, mask_secrets))
        
        elif section == "key_rotation":
            if not config.key_rotation_policy:
                raise ValueError("Key rotation policy is not set")
            lines.extend(self._format_key_rotation_policy(config.key_rotation_policy))
        
        elif section == "rate_limits":
            if not config.rate_limit_policies:
                raise ValueError("Rate limit policies are not set")
            lines.extend(self._format_rate_limit_policies(config.rate_limit_policies))
        
        elif section == "anomaly_detection":
            if not config.anomaly_detection_config:
                raise ValueError("Anomaly detection configuration is not set")
            lines.extend(self._format_anomaly_detection_config(config.anomaly_detection_config))
        
        elif section == "incident_response":
            if not config.incident_response_rules:
                raise ValueError("Incident response rules are not set")
            lines.extend(self._format_incident_response_rules(config.incident_response_rules))
        
        elif section == "mfa":
            if not config.mfa_requirements:
                raise ValueError("MFA requirements are not set")
            lines.extend(self._format_mfa_requirements(config.mfa_requirements))
        
        else:
            raise ValueError(
                f"Invalid section '{section}'. Valid sections: tls, key_rotation, "
                "rate_limits, anomaly_detection, incident_response, mfa"
            )
        
        return "\n".join(lines)
    
    def _mask_value(self, value: str, mask: bool = True) -> str:
        """Mask a sensitive value.
        
        Validates Requirement 22.3: Mask sensitive values in output
        
        Args:
            value: Value to potentially mask
            mask: Whether to apply masking
            
        Returns:
            Masked value or original value
        """
        if mask:
            return "***MASKED***"
        return value
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field name indicates sensitive data.
        
        Args:
            field_name: Field name to check
            
        Returns:
            True if field appears to contain sensitive data
        """
        field_lower = field_name.lower()
        return any(pattern in field_lower for pattern in self.SENSITIVE_PATTERNS)
    
    def _format_tls_config(self, tls_config: TLSConfig, mask_secrets: bool) -> List[str]:
        """Format TLS configuration section.
        
        Args:
            tls_config: TLS configuration object
            mask_secrets: Whether to mask sensitive values
            
        Returns:
            List of formatted lines
        """
        lines = []
        lines.append("# TLS/SSL Configuration for WebSocket Server")
        lines.append("# Provides encrypted transport layer for robot-to-control-plane communications")
        lines.append("tls:")
        
        # Certificate path
        lines.append("  # Path to TLS certificate file (PEM format)")
        cert_path = self._mask_value(tls_config.cert_path, mask_secrets)
        lines.append(f"  cert_path: {cert_path}")
        
        # Key path
        lines.append("  # Path to TLS private key file (PEM format)")
        key_path = self._mask_value(tls_config.key_path, mask_secrets)
        lines.append(f"  key_path: {key_path}")
        
        # Protocols
        lines.append("  # Allowed TLS protocol versions")
        lines.append("  protocols:")
        for protocol in tls_config.protocols:
            lines.append(f"    - {protocol}")
        
        # Cipher suites (optional)
        if tls_config.cipher_suites:
            lines.append("  # Allowed cipher suites (optional)")
            lines.append("  cipher_suites:")
            for cipher in tls_config.cipher_suites:
                lines.append(f"    - {cipher}")
        
        return lines
    
    def _format_key_rotation_policy(self, policy: KeyRotationPolicy) -> List[str]:
        """Format key rotation policy section.
        
        Args:
            policy: Key rotation policy object
            
        Returns:
            List of formatted lines
        """
        lines = []
        lines.append("# Key Rotation Policy")
        lines.append("# Defines automatic cryptographic key rotation behavior")
        lines.append("key_rotation:")
        
        # Rotation interval
        lines.append("  # Hours between automatic key rotations (1-720)")
        lines.append(f"  rotation_interval_hours: {policy.rotation_interval_hours}")
        
        # Grace period
        lines.append("  # Minutes to keep old key valid for in-flight messages")
        lines.append(f"  grace_period_minutes: {policy.grace_period_minutes}")
        
        # Auto-rotate master key
        lines.append("  # Whether to automatically rotate the master key")
        lines.append(f"  auto_rotate_master_key: {str(policy.auto_rotate_master_key).lower()}")
        
        return lines
    
    def _format_rate_limit_policies(self, policies: List[RateLimitPolicy]) -> List[str]:
        """Format rate limit policies section.
        
        Args:
            policies: List of rate limit policy objects
            
        Returns:
            List of formatted lines
        """
        lines = []
        lines.append("# API Rate Limiting Policies")
        lines.append("# Enforces request frequency limits per client to prevent abuse")
        lines.append("rate_limits:")
        
        for policy in policies:
            # Endpoint pattern
            lines.append(f"  # Rate limit for {policy.endpoint_pattern}")
            lines.append(f"  - endpoint_pattern: \"{policy.endpoint_pattern}\"")
            
            # Requests per window
            lines.append(f"    # Maximum requests allowed per time window")
            lines.append(f"    requests_per_window: {policy.requests_per_window}")
            
            # Window duration
            lines.append(f"    # Time window in seconds")
            lines.append(f"    window_seconds: {policy.window_seconds}")
            
            # Role overrides
            if policy.role_overrides:
                lines.append(f"    # Role-specific request limits")
                lines.append(f"    role_overrides:")
                for role, limit in policy.role_overrides.items():
                    lines.append(f"      {role}: {limit}")
            
            lines.append("")
        
        # Remove trailing empty line
        if lines and lines[-1] == "":
            lines.pop()
        
        return lines
    
    def _format_anomaly_detection_config(self, config: AnomalyDetectionConfig) -> List[str]:
        """Format anomaly detection configuration section.
        
        Args:
            config: Anomaly detection configuration object
            
        Returns:
            List of formatted lines
        """
        lines = []
        lines.append("# Anomaly Detection Configuration")
        lines.append("# Monitors robot behavior for security anomalies")
        lines.append("anomaly_detection:")
        
        # Baseline window
        lines.append("  # Hours of historical data to use for baseline learning")
        lines.append(f"  baseline_window_hours: {config.baseline_window_hours}")
        
        # Z-score threshold
        lines.append("  # Z-score threshold for anomaly detection (standard deviations)")
        lines.append(f"  z_score_threshold: {config.z_score_threshold}")
        
        # Sensitivity
        lines.append("  # Sensitivity level: low, medium, high")
        lines.append(f"  sensitivity: {config.sensitivity}")
        
        # Monitored features
        lines.append("  # Features to monitor for anomalies")
        lines.append("  monitored_features:")
        for feature in config.monitored_features:
            lines.append(f"    - {feature}")
        
        return lines
    
    def _format_incident_response_rules(self, rules: List[ResponseRule]) -> List[str]:
        """Format incident response rules section.
        
        Args:
            rules: List of incident response rule objects
            
        Returns:
            List of formatted lines
        """
        lines = []
        lines.append("# Incident Response Rules")
        lines.append("# Automated actions taken when security threats are detected")
        lines.append("incident_response:")
        
        for rule in rules:
            # Alert category
            lines.append(f"  # Response for {rule.alert_category} alerts")
            lines.append(f"  - alert_category: {rule.alert_category}")
            
            # Severity threshold
            lines.append(f"    # Minimum severity to trigger: critical, high, medium, low")
            lines.append(f"    severity_threshold: {rule.severity_threshold}")
            
            # Actions
            lines.append(f"    # Actions to execute: revoke_cert, block_client, extend_rate_limit")
            lines.append(f"    actions:")
            for action in rule.actions:
                lines.append(f"      - {action}")
            
            # Auto-execute
            lines.append(f"    # Whether to execute automatically without manual approval")
            lines.append(f"    auto_execute: {str(rule.auto_execute).lower()}")
            
            lines.append("")
        
        # Remove trailing empty line
        if lines and lines[-1] == "":
            lines.pop()
        
        return lines
    
    def _format_mfa_requirements(self, mfa_requirements: Dict[str, bool]) -> List[str]:
        """Format MFA requirements section.
        
        Args:
            mfa_requirements: Dictionary mapping role names to MFA requirement
            
        Returns:
            List of formatted lines
        """
        lines = []
        lines.append("# Multi-Factor Authentication Requirements")
        lines.append("# Maps role names to whether MFA is required for that role")
        lines.append("mfa_requirements:")
        
        for role, required in sorted(mfa_requirements.items()):
            lines.append(f"  {role}: {str(required).lower()}")
        
        return lines
