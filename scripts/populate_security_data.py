"""
Populate security dashboard with sample data for testing.

This script adds sample security events to demonstrate the dashboard functionality.
"""

import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.audit_logger import AuditLogger
from app.core.key_manager import KeyManager, KeyRotationPolicy
from app.core.certificate_manager import CertificateManager
from app.core.anomaly_detector import AnomalyDetector, AnomalyDetectionConfig, RobotMetrics


def populate_data():
    """Populate security components with sample data."""
    
    print("Initializing security components...")
    
    # Initialize AuditLogger
    audit_logger = AuditLogger(
        signing_key_path="audit_signing_key.pem",
        genesis_hash_path="genesis_hash.txt",
        storage_path="audit_events.json"
    )
    
    # Initialize KeyManager
    key_manager = KeyManager(
        master_key_source="master_key.bin",
        rotation_policy=KeyRotationPolicy()
    )
    key_manager.set_audit_logger(audit_logger)
    
    # Initialize CertificateManager
    cert_manager = CertificateManager(
        ca_cert_path="ca_cert.pem",
        ca_key_path="ca_key.pem",
        crl_storage_path="crl.json"
    )
    cert_manager.set_audit_logger(audit_logger)
    
    # Initialize AnomalyDetector
    anomaly_config = AnomalyDetectionConfig(
        baseline_window_hours=24,
        z_score_threshold=3.0,
        sensitivity="medium",
        monitored_features=["battery_level", "task_completion_time", "message_frequency", "movement_speed"]
    )
    anomaly_detector = AnomalyDetector(config=anomaly_config, audit_logger=audit_logger)
    
    print("\n1. Creating robot key pairs...")
    # Generate key pairs for 4 robots
    for i in range(1, 5):
        robot_id = f"dog{i}"
        key_manager.generate_robot_keypair(robot_id)
        print(f"   - Generated key pair for {robot_id}")
    
    print("\n2. Issuing robot certificates...")
    # Issue certificates for robots
    for i in range(1, 5):
        robot_id = f"dog{i}"
        key_pair = key_manager.robot_keys[robot_id]
        cert_manager.issue_robot_certificate(
            robot_id=robot_id,
            public_key=key_pair.public_key,
            validity_days=365
        )
        print(f"   - Issued certificate for {robot_id}")
    
    print("\n3. Revoking one certificate...")
    # Revoke one certificate
    cert_manager.revoke_certificate("dog4", reason="Testing revocation")
    print("   - Revoked certificate for dog4")
    
    print("\n4. Creating session keys...")
    # Create some session keys
    for i in range(1, 4):
        session_id = f"session_{i}"
        key_manager.derive_session_key(session_id, f"key_{i}")
        print(f"   - Created session key for {session_id}")
    
    print("\n5. Logging security events...")
    
    # Log some blocked attacks
    attack_types = ["sql_injection", "xss", "replay_attack", "unsigned_injection"]
    for i, attack_type in enumerate(attack_types):
        audit_logger.log_event(
            category="threat_blocked",
            title=f"Blocked {attack_type} attack",
            actor="security_system",
            details={
                "attack_type": attack_type,
                "source_ip": f"192.168.1.{100 + i}",
                "target": f"dog{(i % 3) + 1}",
                "timestamp": time.time() - (i * 3600)  # Spread over last few hours
            }
        )
        print(f"   - Logged {attack_type} attack")
    
    # Log some authentication events
    for i in range(5):
        success = i < 3  # First 3 succeed, last 2 fail
        audit_logger.log_event(
            category="authentication",
            title=f"Authentication {'succeeded' if success else 'failed'}",
            actor=f"user_{i}",
            details={
                "success": success,
                "method": "certificate",
                "robot_id": f"dog{(i % 4) + 1}",
                "timestamp": time.time() - (i * 1800)
            }
        )
        print(f"   - Logged authentication {'success' if success else 'failure'}")
    
    # Log some anomaly detections (simplified - just log events directly)
    for i in range(3):
        robot_id = f"dog{i + 1}"
        audit_logger.log_event(
            category="anomaly_alert",
            title=f"Anomaly detected for {robot_id}",
            actor="anomaly_detector",
            details={
                "robot_id": robot_id,
                "anomaly_score": 4.5 + i * 0.5,
                "anomalous_features": ["battery_level"] if i == 0 else ["task_completion_time"] if i == 1 else ["message_frequency"],
                "timestamp": time.time() - (i * 3600)
            }
        )
        print(f"   - Logged anomaly detection for {robot_id}")
    
    print("\n6. Verifying data...")
    
    # Verify data
    print(f"   - Active robots: {len([k for k in key_manager.robot_keys.values() if not k.revoked])}")
    print(f"   - Revoked certificates: {len(cert_manager.crl)}")
    print(f"   - Active sessions: {len(key_manager.session_keys)}")
    print(f"   - Audit events: {len(audit_logger.events)}")
    print(f"   - Blocked attacks: {len(audit_logger.get_events_by_category('threat_blocked'))}")
    print(f"   - Authentication events: {len(audit_logger.get_events_by_category('authentication'))}")
    print(f"   - Anomaly alerts: {len(audit_logger.get_events_by_category('anomaly_alert'))}")
    
    print("\n✅ Sample data populated successfully!")
    print("\nNow refresh the security dashboard to see the data.")
    print("URL: http://localhost:8000/security-dashboard")


if __name__ == "__main__":
    populate_data()
