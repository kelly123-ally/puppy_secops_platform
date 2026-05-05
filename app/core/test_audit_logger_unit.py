"""
Unit Tests for Audit Logger

Tests specific examples and edge cases for audit logging.

Requirements: 9.1-9.6, 10.1-10.5, 11.1-11.6, 24.1-24.6
"""

import json
import tempfile
import time
from pathlib import Path

import pytest

from app.core.audit_logger import AuditLogger


class TestAuditEventCreation:
    """Test audit event creation and storage."""
    
    def test_log_event(self):
        """Test logging a basic audit event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                signing_key_path=str(Path(tmpdir) / "key.pem"),
                genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
                storage_path=str(Path(tmpdir) / "events.json")
            )
            
            event_id = logger.log_event(
                category="authentication",
                title="User login",
                actor="admin",
                details={"ip": "192.168.1.1"}
            )
            
            assert event_id is not None
            assert len(logger.events) == 1
            assert logger.events[0].category == "authentication"
    
    def test_multiple_events_form_chain(self):
        """Test that multiple events form a proper chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                signing_key_path=str(Path(tmpdir) / "key.pem"),
                genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
                storage_path=str(Path(tmpdir) / "events.json")
            )
            
            logger.log_event("auth", "Event 1", "user1", {})
            logger.log_event("auth", "Event 2", "user2", {})
            logger.log_event("auth", "Event 3", "user3", {})
            
            # Check chain linking
            assert logger.events[1].previous_hash == logger.events[0].event_hash
            assert logger.events[2].previous_hash == logger.events[1].event_hash


class TestChainIntegrity:
    """Test audit chain integrity verification."""
    
    def test_verify_untampered_chain(self):
        """Test that untampered chain passes verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                signing_key_path=str(Path(tmpdir) / "key.pem"),
                genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
                storage_path=str(Path(tmpdir) / "events.json")
            )
            
            for i in range(5):
                logger.log_event("test", f"Event {i}", "system", {})
            
            valid, tampered_index = logger.verify_chain_integrity()
            assert valid
            assert tampered_index is None
    
    def test_detect_tampered_event(self):
        """Test that tampering is detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                signing_key_path=str(Path(tmpdir) / "key.pem"),
                genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
                storage_path=str(Path(tmpdir) / "events.json")
            )
            
            for i in range(5):
                logger.log_event("test", f"Event {i}", "system", {})
            
            # Tamper with event
            logger.events[2].title = "TAMPERED"
            
            valid, tampered_index = logger.verify_chain_integrity()
            assert not valid
            assert tampered_index == 2


class TestComplianceExport:
    """Test compliance report export."""
    
    def test_export_json(self):
        """Test exporting compliance report as JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                signing_key_path=str(Path(tmpdir) / "key.pem"),
                genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
                storage_path=str(Path(tmpdir) / "events.json")
            )
            
            start_time = time.time()
            logger.log_event("test", "Event 1", "system", {})
            logger.log_event("test", "Event 2", "system", {})
            end_time = time.time()
            
            report = logger.export_compliance_report(
                start_time=start_time,
                end_time=end_time,
                format="json"
            )
            
            # Parse JSON
            report_data = json.loads(report)
            assert "events" in report_data
            assert len(report_data["events"]) == 2
    
    def test_export_csv(self):
        """Test exporting compliance report as CSV."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                signing_key_path=str(Path(tmpdir) / "key.pem"),
                genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
                storage_path=str(Path(tmpdir) / "events.json")
            )
            
            start_time = time.time()
            logger.log_event("test", "Event 1", "system", {})
            end_time = time.time()
            
            report = logger.export_compliance_report(
                start_time=start_time,
                end_time=end_time,
                format="csv"
            )
            
            # Check CSV format
            assert b"event_id" in report
            assert b"Event 1" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
