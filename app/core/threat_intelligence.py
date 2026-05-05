"""
Threat Intelligence Integration for PuppySecOps Platform

Provides threat intelligence integration including:
- Loading threat intelligence data from external JSON files
- Malicious IP address blocking (with CIDR notation support)
- Attack signature detection and blocking (regex-based)
- Compromised credential detection
- Periodic refresh of threat intelligence data
- Integration with audit logger for blocked threats

Requirements: 20.1-20.6
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.audit_logger import AuditLogger


@dataclass
class ThreatIntelligenceData:
    """Threat intelligence data loaded from external sources.
    
    Attributes:
        malicious_ips: Set of malicious IP addresses and CIDR ranges
        attack_signatures: List of attack signature patterns (regex)
        compromised_credentials: Set of compromised credential hashes
        last_updated: Unix timestamp of last data update
        source: Source identifier for the threat intelligence data
    """
    malicious_ips: Set[str] = field(default_factory=set)
    attack_signatures: List[str] = field(default_factory=list)
    compromised_credentials: Set[str] = field(default_factory=set)
    last_updated: float = 0.0
    source: str = "unknown"


class ThreatIntelligence:
    """Threat intelligence integration for blocking known threats.
    
    Loads threat intelligence from external JSON files and provides
    methods to check connections, commands, and credentials against
    known threat indicators.
    
    Validates Requirements:
    - 20.1: Support loading threat intelligence from external JSON files
    - 20.2: Include malicious IPs, attack signatures, compromised credentials
    - 20.3: Reject connections from known malicious IP addresses
    - 20.4: Block commands matching known attack signatures
    - 20.5: Support periodic refresh of threat intelligence data
    - 20.6: Log threat intelligence updates and blocked threats
    """
    
    def __init__(
        self,
        data_path: Optional[str] = None,
        audit_logger: Optional[AuditLogger] = None,
        auto_refresh_interval: Optional[float] = None
    ):
        """Initialize Threat Intelligence system.
        
        Implements Requirement 20.1: Load threat intelligence from external JSON files
        
        Args:
            data_path: Path to threat intelligence JSON file
            audit_logger: Optional audit logger for logging threat events
            auto_refresh_interval: Optional interval in seconds for automatic refresh (e.g., 3600 for hourly)
        """
        self.data_path = data_path or "threat_intelligence.json"
        self.audit_logger = audit_logger
        self.auto_refresh_interval = auto_refresh_interval
        
        # Threat intelligence data
        self.threat_data = ThreatIntelligenceData()
        
        # Compiled regex patterns for attack signatures (cached for performance)
        self._compiled_signatures: List[re.Pattern] = []
        
        # Parsed IP networks for CIDR matching (cached for performance)
        self._ip_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        
        # Statistics
        self.blocked_connections = 0
        self.blocked_commands = 0
        self.blocked_credentials = 0
        
        # Last refresh time
        self.last_refresh_time = 0.0
        
        # Load initial data
        self.load_threat_intelligence()
    
    def load_threat_intelligence(self, data_path: Optional[str] = None) -> bool:
        """Load threat intelligence data from external JSON file.
        
        Implements Requirements 20.1, 20.2:
        - Load from external JSON files
        - Include malicious IPs, attack signatures, compromised credentials
        
        Expected JSON format:
        {
            "source": "threat_feed_name",
            "updated": 1234567890.0,
            "malicious_ips": ["192.168.1.100", "10.0.0.0/8", "2001:db8::/32"],
            "attack_signatures": [
                "rm -rf /",
                "DROP TABLE.*",
                "eval\\(.*\\)"
            ],
            "compromised_credentials": [
                "5f4dcc3b5aa765d61d8327deb882cf99",
                "098f6bcd4621d373cade4e832627b4f6"
            ]
        }
        
        Args:
            data_path: Optional path to JSON file (uses default if not provided)
            
        Returns:
            True if data loaded successfully, False otherwise
        """
        path = Path(data_path or self.data_path)
        
        if not path.exists():
            # No threat intelligence file, start with empty data
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Threat intelligence file not found",
                    actor="system",
                    details={
                        "path": str(path),
                        "message": "Starting with empty threat intelligence data"
                    }
                )
            return False
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            # Parse threat intelligence data
            self.threat_data = ThreatIntelligenceData(
                malicious_ips=set(data.get("malicious_ips", [])),
                attack_signatures=data.get("attack_signatures", []),
                compromised_credentials=set(data.get("compromised_credentials", [])),
                last_updated=data.get("updated", time.time()),
                source=data.get("source", "unknown")
            )
            
            # Compile attack signature patterns
            self._compile_attack_signatures()
            
            # Parse IP networks for CIDR matching
            self._parse_ip_networks()
            
            # Update refresh time
            self.last_refresh_time = time.time()
            
            # Log successful load (Requirement 20.6)
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Threat intelligence data loaded",
                    actor="system",
                    details={
                        "source": self.threat_data.source,
                        "malicious_ips_count": len(self.threat_data.malicious_ips),
                        "attack_signatures_count": len(self.threat_data.attack_signatures),
                        "compromised_credentials_count": len(self.threat_data.compromised_credentials),
                        "data_updated": self.threat_data.last_updated,
                        "path": str(path)
                    }
                )
            
            return True
            
        except Exception as e:
            # Log load failure
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Failed to load threat intelligence data",
                    actor="system",
                    details={
                        "path": str(path),
                        "error": str(e)
                    }
                )
            return False
    
    def _compile_attack_signatures(self) -> None:
        """Compile attack signature patterns into regex objects.
        
        Caches compiled patterns for performance.
        """
        self._compiled_signatures = []
        
        for pattern in self.threat_data.attack_signatures:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled_signatures.append(compiled)
            except re.error:
                # Invalid regex pattern, skip it
                if self.audit_logger:
                    self.audit_logger.log_event(
                        category="threat_intelligence",
                        title="Invalid attack signature pattern",
                        actor="system",
                        details={
                            "pattern": pattern,
                            "error": "Invalid regex syntax"
                        }
                    )
    
    def _parse_ip_networks(self) -> None:
        """Parse IP addresses and CIDR ranges into network objects.
        
        Caches parsed networks for performance.
        """
        self._ip_networks = []
        
        for ip_str in self.threat_data.malicious_ips:
            try:
                # Try to parse as network (supports both single IPs and CIDR)
                network = ipaddress.ip_network(ip_str, strict=False)
                self._ip_networks.append(network)
            except ValueError:
                # Invalid IP address or CIDR, skip it
                if self.audit_logger:
                    self.audit_logger.log_event(
                        category="threat_intelligence",
                        title="Invalid IP address or CIDR",
                        actor="system",
                        details={
                            "ip_string": ip_str,
                            "error": "Invalid IP address or CIDR notation"
                        }
                    )
    
    def is_malicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is known to be malicious.
        
        Implements Requirement 20.3: Reject connections from known malicious IPs
        
        Supports both exact IP matching and CIDR range matching.
        
        Args:
            ip_address: IP address to check (IPv4 or IPv6)
            
        Returns:
            True if IP is malicious, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check against all known malicious networks
            for network in self._ip_networks:
                if ip in network:
                    # Log blocked connection (Requirement 20.6)
                    if self.audit_logger:
                        self.audit_logger.log_event(
                            category="threat_intelligence",
                            title="Malicious IP connection blocked",
                            actor="system",
                            details={
                                "ip_address": ip_address,
                                "matched_network": str(network),
                                "source": self.threat_data.source
                            }
                        )
                    
                    self.blocked_connections += 1
                    return True
            
            return False
            
        except ValueError:
            # Invalid IP address format
            return False
    
    def contains_attack_signature(self, command: str) -> Optional[str]:
        """Check if command contains known attack signature.
        
        Implements Requirement 20.4: Block commands matching known attack signatures
        
        Args:
            command: Command string to check
            
        Returns:
            Matched attack signature pattern if found, None otherwise
        """
        for pattern in self._compiled_signatures:
            if pattern.search(command):
                matched_pattern = pattern.pattern
                
                # Log blocked command (Requirement 20.6)
                if self.audit_logger:
                    self.audit_logger.log_event(
                        category="threat_intelligence",
                        title="Attack signature detected in command",
                        actor="system",
                        details={
                            "command": command,
                            "matched_signature": matched_pattern,
                            "source": self.threat_data.source
                        }
                    )
                
                self.blocked_commands += 1
                return matched_pattern
        
        return None
    
    def is_compromised_credential(self, credential_hash: str) -> bool:
        """Check if credential hash is known to be compromised.
        
        Implements Requirement 20.2: Support compromised credentials detection
        
        Args:
            credential_hash: Hash of credential to check (e.g., MD5, SHA256)
            
        Returns:
            True if credential is compromised, False otherwise
        """
        if credential_hash in self.threat_data.compromised_credentials:
            # Log compromised credential detection
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Compromised credential detected",
                    actor="system",
                    details={
                        "credential_hash": credential_hash,
                        "source": self.threat_data.source
                    }
                )
            
            self.blocked_credentials += 1
            return True
        
        return False
    
    def refresh_threat_intelligence(self) -> bool:
        """Refresh threat intelligence data from external source.
        
        Implements Requirement 20.5: Support periodic refresh of threat intelligence data
        
        Returns:
            True if refresh successful, False otherwise
        """
        success = self.load_threat_intelligence()
        
        if success:
            # Log successful refresh (Requirement 20.6)
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Threat intelligence data refreshed",
                    actor="system",
                    details={
                        "source": self.threat_data.source,
                        "malicious_ips_count": len(self.threat_data.malicious_ips),
                        "attack_signatures_count": len(self.threat_data.attack_signatures),
                        "compromised_credentials_count": len(self.threat_data.compromised_credentials),
                        "data_updated": self.threat_data.last_updated
                    }
                )
        
        return success
    
    def should_auto_refresh(self) -> bool:
        """Check if automatic refresh should occur.
        
        Implements Requirement 20.5: Support periodic refresh
        
        Returns:
            True if refresh interval has elapsed, False otherwise
        """
        if not self.auto_refresh_interval:
            return False
        
        elapsed = time.time() - self.last_refresh_time
        return elapsed >= self.auto_refresh_interval
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics.
        
        Returns:
            Dictionary containing statistics
        """
        return {
            "source": self.threat_data.source,
            "last_updated": self.threat_data.last_updated,
            "last_refresh_time": self.last_refresh_time,
            "malicious_ips_count": len(self.threat_data.malicious_ips),
            "attack_signatures_count": len(self.threat_data.attack_signatures),
            "compromised_credentials_count": len(self.threat_data.compromised_credentials),
            "blocked_connections": self.blocked_connections,
            "blocked_commands": self.blocked_commands,
            "blocked_credentials": self.blocked_credentials
        }
    
    def add_malicious_ip(self, ip_address: str) -> bool:
        """Manually add malicious IP address.
        
        Args:
            ip_address: IP address or CIDR range to add
            
        Returns:
            True if added successfully, False if invalid
        """
        try:
            # Validate IP address or CIDR
            ipaddress.ip_network(ip_address, strict=False)
            
            # Add to threat data
            self.threat_data.malicious_ips.add(ip_address)
            
            # Reparse IP networks
            self._parse_ip_networks()
            
            # Log addition
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Malicious IP added manually",
                    actor="admin",
                    details={
                        "ip_address": ip_address
                    }
                )
            
            return True
            
        except ValueError:
            return False
    
    def add_attack_signature(self, pattern: str) -> bool:
        """Manually add attack signature pattern.
        
        Args:
            pattern: Regex pattern to add
            
        Returns:
            True if added successfully, False if invalid regex
        """
        try:
            # Validate regex pattern
            re.compile(pattern, re.IGNORECASE)
            
            # Add to threat data
            self.threat_data.attack_signatures.append(pattern)
            
            # Recompile signatures
            self._compile_attack_signatures()
            
            # Log addition
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Attack signature added manually",
                    actor="admin",
                    details={
                        "pattern": pattern
                    }
                )
            
            return True
            
        except re.error:
            return False
    
    def add_compromised_credential(self, credential_hash: str) -> None:
        """Manually add compromised credential hash.
        
        Args:
            credential_hash: Hash of compromised credential
        """
        self.threat_data.compromised_credentials.add(credential_hash)
        
        # Log addition
        if self.audit_logger:
            self.audit_logger.log_event(
                category="threat_intelligence",
                title="Compromised credential added manually",
                actor="admin",
                details={
                    "credential_hash": credential_hash
                }
            )
    
    def export_threat_intelligence(self, output_path: Optional[str] = None) -> bool:
        """Export current threat intelligence data to JSON file.
        
        Args:
            output_path: Optional path to export file (uses default if not provided)
            
        Returns:
            True if export successful, False otherwise
        """
        path = Path(output_path or self.data_path)
        
        try:
            data = {
                "source": self.threat_data.source,
                "updated": time.time(),
                "malicious_ips": list(self.threat_data.malicious_ips),
                "attack_signatures": self.threat_data.attack_signatures,
                "compromised_credentials": list(self.threat_data.compromised_credentials)
            }
            
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Log export
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Threat intelligence data exported",
                    actor="admin",
                    details={
                        "path": str(path)
                    }
                )
            
            return True
            
        except Exception as e:
            # Log export failure
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="threat_intelligence",
                    title="Failed to export threat intelligence data",
                    actor="system",
                    details={
                        "path": str(path),
                        "error": str(e)
                    }
                )
            return False


if __name__ == "__main__":
    # Example usage
    from app.core.audit_logger import AuditLogger
    
    # Create audit logger
    logger = AuditLogger(
        signing_key_path="test_threat_signing_key.pem",
        genesis_hash_path="test_threat_genesis.txt",
        storage_path="test_threat_events.json"
    )
    
    # Create threat intelligence system with hourly refresh
    threat_intel = ThreatIntelligence(
        data_path="threat_intelligence.json",
        audit_logger=logger,
        auto_refresh_interval=3600  # 1 hour
    )
    
    # Check malicious IP
    if threat_intel.is_malicious_ip("192.168.1.100"):
        print("Connection from malicious IP blocked!")
    
    # Check attack signature
    command = "rm -rf /"
    if threat_intel.contains_attack_signature(command):
        print(f"Attack signature detected in command: {command}")
    
    # Check compromised credential
    credential_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    if threat_intel.is_compromised_credential(credential_hash):
        print("Compromised credential detected!")
    
    # Get statistics
    stats = threat_intel.get_statistics()
    print(f"Threat Intelligence Statistics: {stats}")
    
    # Check if auto-refresh needed
    if threat_intel.should_auto_refresh():
        print("Refreshing threat intelligence data...")
        threat_intel.refresh_threat_intelligence()
