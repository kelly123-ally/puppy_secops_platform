"""
Security Configuration Parser for PuppySecOps Platform

Provides configuration parsing including:
- YAML configuration file parsing
- Schema validation and required field checking
- Descriptive error messages for parsing failures
- Support for all security configuration sections
- Hot-reload of configuration without restart

Requirements: 21.1-21.6
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    raise ImportError(
        "pyyaml is required for configuration parsing. "
        "Install it with: pip install pyyaml"
    )

from app.core.access_controller import Permission, RateLimitPolicy, Role
from app.core.anomaly_detector import AnomalyDetectionConfig
from app.core.incident_response import ResponseRule
from app.core.key_manager import KeyRotationPolicy


@dataclass
class TLSConfig:
    """TLS configuration for WebSocket server.
    
    Attributes:
        cert_path: Path to TLS certificate file
        key_path: Path to TLS private key file
        protocols: List of allowed TLS protocols (e.g., ["TLSv1.2", "TLSv1.3"])
        cipher_suites: Optional list of allowed cipher suites
    """
    cert_path: str
    key_path: str
    protocols: List[str] = field(default_factory=lambda: ["TLSv1.2", "TLSv1.3"])
    cipher_suites: Optional[List[str]] = None


@dataclass
class SecurityConfig:
    """Complete security configuration for the platform.
    
    Attributes:
        tls_config: TLS/SSL configuration
        key_rotation_policy: Key rotation policy
        rate_limit_policies: List of rate limiting policies
        anomaly_detection_config: Anomaly detection configuration
        incident_response_rules: List of incident response rules
        mfa_requirements: Role -> MFA required mapping
    """
    tls_config: Optional[TLSConfig] = None
    key_rotation_policy: Optional[KeyRotationPolicy] = None
    rate_limit_policies: List[RateLimitPolicy] = field(default_factory=list)
    anomaly_detection_config: Optional[AnomalyDetectionConfig] = None
    incident_response_rules: List[ResponseRule] = field(default_factory=list)
    mfa_requirements: Dict[str, bool] = field(default_factory=dict)


class SecurityConfigParser:
    """Parses and validates security configuration from YAML files.
    
    Validates Requirements:
    - 21.1: Parse security configuration files in YAML format
    - 21.2: Support configuration for key rotation, rate limits, MFA, anomaly detection, incident response
    - 21.3: Validate configuration schema and reject invalid configurations
    - 21.4: Return descriptive error messages for parsing failures
    - 21.5: Support hot-reloading configuration without restart
    - 21.6: Log configuration changes to audit logger
    """
    
    def __init__(self, audit_logger: Optional[Any] = None):
        """Initialize SecurityConfigParser.
        
        Args:
            audit_logger: Optional AuditLogger instance for logging configuration changes
        """
        self.audit_logger = audit_logger
        self._current_config: Optional[SecurityConfig] = None
        self._current_config_path: Optional[str] = None
        self._config_change_callbacks: List[Callable[[SecurityConfig], None]] = []
    
    def register_config_change_callback(
        self, 
        callback: Callable[[SecurityConfig], None]
    ) -> None:
        """Register a callback to be invoked when configuration changes.
        
        Args:
            callback: Function to call with new SecurityConfig when config is reloaded
        """
        self._config_change_callbacks.append(callback)
    
    def reload_config(self) -> Tuple[bool, Optional[str]]:
        """Reload configuration from the last loaded config file.
        
        Implements Requirements 21.5, 21.6:
        - Reloads configuration without requiring restart
        - Logs configuration changes to audit logger
        
        Returns:
            Tuple of (success, error_message)
            - success: True if reload succeeded, False otherwise
            - error_message: Description of error if reload failed, None if successful
            
        Raises:
            RuntimeError: If no configuration has been loaded yet
        """
        if self._current_config_path is None:
            raise RuntimeError(
                "Cannot reload configuration: no configuration file has been loaded yet. "
                "Call parse_config() first."
            )
        
        try:
            # Parse the new configuration
            new_config = self.parse_config(self._current_config_path)
            
            # Compute configuration changes for audit logging
            changes = self._compute_config_changes(self._current_config, new_config)
            
            # Update current configuration
            old_config = self._current_config
            self._current_config = new_config
            
            # Log configuration change to audit logger
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="configuration",
                    title="Configuration reloaded",
                    actor="system",
                    details={
                        "config_path": self._current_config_path,
                        "changes": changes,
                        "timestamp": __import__('time').time()
                    }
                )
            
            # Notify registered callbacks
            for callback in self._config_change_callbacks:
                try:
                    callback(new_config)
                except Exception as e:
                    # Log callback errors but don't fail the reload
                    if self.audit_logger:
                        self.audit_logger.log_event(
                            category="configuration",
                            title="Configuration callback error",
                            actor="system",
                            details={
                                "error": str(e),
                                "callback": callback.__name__ if hasattr(callback, '__name__') else str(callback)
                            }
                        )
            
            return True, None
            
        except Exception as e:
            error_message = f"Configuration reload failed: {e}"
            
            # Log reload failure to audit logger
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="configuration",
                    title="Configuration reload failed",
                    actor="system",
                    details={
                        "config_path": self._current_config_path,
                        "error": str(e),
                        "timestamp": __import__('time').time()
                    }
                )
            
            return False, error_message
    
    def _compute_config_changes(
        self, 
        old_config: Optional[SecurityConfig], 
        new_config: SecurityConfig
    ) -> Dict[str, Any]:
        """Compute differences between old and new configuration.
        
        Args:
            old_config: Previous configuration (None if first load)
            new_config: New configuration
            
        Returns:
            Dictionary describing configuration changes
        """
        if old_config is None:
            return {"type": "initial_load"}
        
        changes = {}
        
        # Check TLS config changes
        if old_config.tls_config != new_config.tls_config:
            changes["tls_config"] = {
                "changed": True,
                "old": self._summarize_tls_config(old_config.tls_config),
                "new": self._summarize_tls_config(new_config.tls_config)
            }
        
        # Check key rotation policy changes
        if old_config.key_rotation_policy != new_config.key_rotation_policy:
            changes["key_rotation_policy"] = {
                "changed": True,
                "old": self._summarize_key_rotation_policy(old_config.key_rotation_policy),
                "new": self._summarize_key_rotation_policy(new_config.key_rotation_policy)
            }
        
        # Check rate limit policy changes
        if old_config.rate_limit_policies != new_config.rate_limit_policies:
            changes["rate_limit_policies"] = {
                "changed": True,
                "old_count": len(old_config.rate_limit_policies),
                "new_count": len(new_config.rate_limit_policies)
            }
        
        # Check anomaly detection config changes
        if old_config.anomaly_detection_config != new_config.anomaly_detection_config:
            changes["anomaly_detection_config"] = {
                "changed": True,
                "old": self._summarize_anomaly_config(old_config.anomaly_detection_config),
                "new": self._summarize_anomaly_config(new_config.anomaly_detection_config)
            }
        
        # Check incident response rule changes
        if old_config.incident_response_rules != new_config.incident_response_rules:
            changes["incident_response_rules"] = {
                "changed": True,
                "old_count": len(old_config.incident_response_rules),
                "new_count": len(new_config.incident_response_rules)
            }
        
        # Check MFA requirement changes
        if old_config.mfa_requirements != new_config.mfa_requirements:
            changes["mfa_requirements"] = {
                "changed": True,
                "old": old_config.mfa_requirements,
                "new": new_config.mfa_requirements
            }
        
        return changes if changes else {"type": "no_changes"}
    
    def _summarize_tls_config(self, config: Optional[TLSConfig]) -> Optional[Dict[str, Any]]:
        """Create a summary of TLS config for audit logging."""
        if config is None:
            return None
        return {
            "cert_path": config.cert_path,
            "key_path": config.key_path,
            "protocols": config.protocols
        }
    
    def _summarize_key_rotation_policy(
        self, 
        policy: Optional[KeyRotationPolicy]
    ) -> Optional[Dict[str, Any]]:
        """Create a summary of key rotation policy for audit logging."""
        if policy is None:
            return None
        return {
            "rotation_interval_hours": policy.rotation_interval_hours,
            "grace_period_minutes": policy.grace_period_minutes,
            "auto_rotate_master_key": policy.auto_rotate_master_key
        }
    
    def _summarize_anomaly_config(
        self, 
        config: Optional[AnomalyDetectionConfig]
    ) -> Optional[Dict[str, Any]]:
        """Create a summary of anomaly detection config for audit logging."""
        if config is None:
            return None
        return {
            "baseline_window_hours": config.baseline_window_hours,
            "z_score_threshold": config.z_score_threshold,
            "sensitivity": config.sensitivity
        }
    
    def get_current_config(self) -> Optional[SecurityConfig]:
        """Get the currently loaded configuration.
        
        Returns:
            Current SecurityConfig or None if no config loaded
        """
        return self._current_config
    
    def parse_config(self, config_path: str) -> SecurityConfig:
        """Parse YAML configuration file and validate schema.
        
        Args:
            config_path: Path to YAML configuration file
            
        Returns:
            SecurityConfig object with parsed configuration
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If configuration is invalid
            yaml.YAMLError: If YAML syntax is invalid
            
        Validates Requirement 21.1: Parse security configuration files in YAML format
        """
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_file, 'r') as f:
                raw_config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML syntax in {config_path}: {e}")
        
        if raw_config is None:
            raise ValueError(f"Configuration file is empty: {config_path}")
        
        if not isinstance(raw_config, dict):
            raise ValueError(
                f"Configuration must be a YAML dictionary, got {type(raw_config).__name__}"
            )
        
        # Parse each configuration section
        try:
            tls_config = self._parse_tls_config(raw_config.get('tls', {}))
            key_rotation_policy = self._parse_key_rotation_policy(
                raw_config.get('key_rotation', {})
            )
            rate_limit_policies = self._parse_rate_limit_policies(
                raw_config.get('rate_limits', [])
            )
            anomaly_detection_config = self._parse_anomaly_detection_config(
                raw_config.get('anomaly_detection', {})
            )
            incident_response_rules = self._parse_incident_response_rules(
                raw_config.get('incident_response', [])
            )
            mfa_requirements = self._parse_mfa_requirements(
                raw_config.get('mfa_requirements', {})
            )
            
            config = SecurityConfig(
                tls_config=tls_config,
                key_rotation_policy=key_rotation_policy,
                rate_limit_policies=rate_limit_policies,
                anomaly_detection_config=anomaly_detection_config,
                incident_response_rules=incident_response_rules,
                mfa_requirements=mfa_requirements
            )
            
            # Validate the complete configuration
            is_valid, errors = self.validate_config(config)
            if not is_valid:
                raise ValueError(
                    f"Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
                )
            
            # Store current config and path for hot-reload
            self._current_config = config
            self._current_config_path = config_path
            
            return config
            
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Configuration parsing error: {e}")
    
    def validate_config(self, config: SecurityConfig) -> Tuple[bool, List[str]]:
        """Validate configuration and return (valid, error_messages).
        
        Args:
            config: SecurityConfig object to validate
            
        Returns:
            Tuple of (is_valid, list_of_error_messages)
            
        Validates Requirement 21.3: Validate configuration schema and required fields
        """
        errors = []
        
        # Validate TLS config
        if config.tls_config:
            tls_errors = self._validate_tls_config(config.tls_config)
            errors.extend(tls_errors)
        
        # Validate key rotation policy
        if config.key_rotation_policy:
            try:
                # KeyRotationPolicy validates itself in __post_init__
                pass
            except ValueError as e:
                errors.append(f"Key rotation policy: {e}")
        
        # Validate rate limit policies
        for i, policy in enumerate(config.rate_limit_policies):
            policy_errors = self._validate_rate_limit_policy(policy, i)
            errors.extend(policy_errors)
        
        # Validate anomaly detection config
        if config.anomaly_detection_config:
            anomaly_errors = self._validate_anomaly_detection_config(
                config.anomaly_detection_config
            )
            errors.extend(anomaly_errors)
        
        # Validate incident response rules
        for i, rule in enumerate(config.incident_response_rules):
            rule_errors = self._validate_incident_response_rule(rule, i)
            errors.extend(rule_errors)
        
        # Validate MFA requirements
        mfa_errors = self._validate_mfa_requirements(config.mfa_requirements)
        errors.extend(mfa_errors)
        
        return (len(errors) == 0, errors)
    
    def _parse_tls_config(self, tls_dict: Dict[str, Any]) -> Optional[TLSConfig]:
        """Parse TLS configuration section."""
        if not tls_dict:
            return None
        
        cert_path = tls_dict.get('cert_path')
        key_path = tls_dict.get('key_path')
        
        if not cert_path or not key_path:
            raise ValueError("TLS config requires both 'cert_path' and 'key_path'")
        
        protocols = tls_dict.get('protocols', ["TLSv1.2", "TLSv1.3"])
        cipher_suites = tls_dict.get('cipher_suites')
        
        return TLSConfig(
            cert_path=cert_path,
            key_path=key_path,
            protocols=protocols,
            cipher_suites=cipher_suites
        )
    
    def _parse_key_rotation_policy(
        self, 
        rotation_dict: Dict[str, Any]
    ) -> Optional[KeyRotationPolicy]:
        """Parse key rotation policy section.
        
        Validates Requirement 21.2: Support configuration for key rotation policies
        """
        if not rotation_dict:
            return None
        
        rotation_interval_hours = rotation_dict.get('rotation_interval_hours', 24)
        grace_period_minutes = rotation_dict.get('grace_period_minutes', 5)
        auto_rotate_master_key = rotation_dict.get('auto_rotate_master_key', False)
        
        return KeyRotationPolicy(
            rotation_interval_hours=rotation_interval_hours,
            grace_period_minutes=grace_period_minutes,
            auto_rotate_master_key=auto_rotate_master_key
        )
    
    def _parse_rate_limit_policies(
        self, 
        policies_list: List[Dict[str, Any]]
    ) -> List[RateLimitPolicy]:
        """Parse rate limit policies section.
        
        Validates Requirement 21.2: Support configuration for rate limits
        """
        policies = []
        
        for policy_dict in policies_list:
            endpoint_pattern = policy_dict.get('endpoint_pattern')
            requests_per_window = policy_dict.get('requests_per_window')
            window_seconds = policy_dict.get('window_seconds')
            
            if not endpoint_pattern:
                raise ValueError("Rate limit policy requires 'endpoint_pattern'")
            if requests_per_window is None:
                raise ValueError("Rate limit policy requires 'requests_per_window'")
            if window_seconds is None:
                raise ValueError("Rate limit policy requires 'window_seconds'")
            
            role_overrides = policy_dict.get('role_overrides', {})
            
            policies.append(RateLimitPolicy(
                endpoint_pattern=endpoint_pattern,
                requests_per_window=requests_per_window,
                window_seconds=window_seconds,
                role_overrides=role_overrides
            ))
        
        return policies
    
    def _parse_anomaly_detection_config(
        self, 
        anomaly_dict: Dict[str, Any]
    ) -> Optional[AnomalyDetectionConfig]:
        """Parse anomaly detection configuration section.
        
        Validates Requirement 21.2: Support configuration for anomaly detection thresholds
        """
        if not anomaly_dict:
            return None
        
        baseline_window_hours = anomaly_dict.get('baseline_window_hours', 24)
        z_score_threshold = anomaly_dict.get('z_score_threshold', 3.0)
        sensitivity = anomaly_dict.get('sensitivity', 'medium')
        monitored_features = anomaly_dict.get('monitored_features', [
            "battery_level",
            "task_completion_time",
            "message_frequency",
            "movement_speed"
        ])
        
        return AnomalyDetectionConfig(
            baseline_window_hours=baseline_window_hours,
            z_score_threshold=z_score_threshold,
            sensitivity=sensitivity,
            monitored_features=monitored_features
        )
    
    def _parse_incident_response_rules(
        self, 
        rules_list: List[Dict[str, Any]]
    ) -> List[ResponseRule]:
        """Parse incident response rules section.
        
        Validates Requirement 21.2: Support configuration for incident response rules
        """
        rules = []
        
        for rule_dict in rules_list:
            alert_category = rule_dict.get('alert_category')
            severity_threshold = rule_dict.get('severity_threshold')
            actions = rule_dict.get('actions', [])
            auto_execute = rule_dict.get('auto_execute', True)
            
            if not alert_category:
                raise ValueError("Incident response rule requires 'alert_category'")
            if not severity_threshold:
                raise ValueError("Incident response rule requires 'severity_threshold'")
            
            rules.append(ResponseRule(
                alert_category=alert_category,
                severity_threshold=severity_threshold,
                actions=actions,
                auto_execute=auto_execute
            ))
        
        return rules
    
    def _parse_mfa_requirements(
        self, 
        mfa_dict: Dict[str, Any]
    ) -> Dict[str, bool]:
        """Parse MFA requirements section.
        
        Validates Requirement 21.2: Support configuration for MFA requirements
        """
        # MFA requirements is a simple dict mapping role names to boolean
        if not isinstance(mfa_dict, dict):
            raise ValueError("MFA requirements must be a dictionary")
        
        # Validate all values are boolean
        for role, required in mfa_dict.items():
            if not isinstance(required, bool):
                raise ValueError(
                    f"MFA requirement for role '{role}' must be boolean, got {type(required).__name__}"
                )
        
        return mfa_dict
    
    def _validate_tls_config(self, tls_config: TLSConfig) -> List[str]:
        """Validate TLS configuration."""
        errors = []
        
        # Check certificate file exists
        if not Path(tls_config.cert_path).exists():
            errors.append(f"TLS certificate file not found: {tls_config.cert_path}")
        
        # Check key file exists
        if not Path(tls_config.key_path).exists():
            errors.append(f"TLS key file not found: {tls_config.key_path}")
        
        # Validate protocols
        valid_protocols = ["TLSv1.2", "TLSv1.3"]
        for protocol in tls_config.protocols:
            if protocol not in valid_protocols:
                errors.append(
                    f"Invalid TLS protocol '{protocol}'. Must be one of: {valid_protocols}"
                )
        
        return errors
    
    def _validate_rate_limit_policy(
        self, 
        policy: RateLimitPolicy, 
        index: int
    ) -> List[str]:
        """Validate rate limit policy."""
        errors = []
        
        if policy.requests_per_window <= 0:
            errors.append(
                f"Rate limit policy {index}: requests_per_window must be positive"
            )
        
        if policy.window_seconds <= 0:
            errors.append(
                f"Rate limit policy {index}: window_seconds must be positive"
            )
        
        # Validate role overrides
        for role, limit in policy.role_overrides.items():
            if limit <= 0:
                errors.append(
                    f"Rate limit policy {index}: role override for '{role}' must be positive"
                )
        
        return errors
    
    def _validate_anomaly_detection_config(
        self, 
        config: AnomalyDetectionConfig
    ) -> List[str]:
        """Validate anomaly detection configuration."""
        errors = []
        
        if config.baseline_window_hours <= 0:
            errors.append("Anomaly detection: baseline_window_hours must be positive")
        
        if config.z_score_threshold <= 0:
            errors.append("Anomaly detection: z_score_threshold must be positive")
        
        valid_sensitivities = ["low", "medium", "high"]
        if config.sensitivity not in valid_sensitivities:
            errors.append(
                f"Anomaly detection: sensitivity must be one of {valid_sensitivities}, "
                f"got '{config.sensitivity}'"
            )
        
        if not config.monitored_features:
            errors.append("Anomaly detection: monitored_features cannot be empty")
        
        return errors
    
    def _validate_incident_response_rule(
        self, 
        rule: ResponseRule, 
        index: int
    ) -> List[str]:
        """Validate incident response rule."""
        errors = []
        
        valid_severities = ["low", "medium", "high", "critical"]
        if rule.severity_threshold not in valid_severities:
            errors.append(
                f"Incident response rule {index}: severity_threshold must be one of "
                f"{valid_severities}, got '{rule.severity_threshold}'"
            )
        
        valid_actions = ["revoke_cert", "block_client", "extend_rate_limit"]
        for action in rule.actions:
            if action not in valid_actions:
                errors.append(
                    f"Incident response rule {index}: invalid action '{action}'. "
                    f"Must be one of {valid_actions}"
                )
        
        if not rule.actions:
            errors.append(
                f"Incident response rule {index}: actions list cannot be empty"
            )
        
        return errors
    
    def _validate_mfa_requirements(self, mfa_requirements: Dict[str, bool]) -> List[str]:
        """Validate MFA requirements."""
        # Already validated during parsing, but double-check
        errors = []
        
        for role, required in mfa_requirements.items():
            if not isinstance(required, bool):
                errors.append(
                    f"MFA requirement for role '{role}' must be boolean"
                )
        
        return errors
