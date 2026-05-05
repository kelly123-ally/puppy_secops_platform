"""
Example usage of AnomalyDetector with AuditLogger integration

This example demonstrates how to use the AnomalyDetector with audit logging
to satisfy Requirement 17.6: Log anomaly detections with robot_id, score, and anomalous features
"""

import time
from app.core.anomaly_detector import (
    AnomalyDetector,
    AnomalyDetectionConfig,
    RobotMetrics
)
from app.core.audit_logger import AuditLogger


def main():
    """Example of anomaly detection with audit logging."""
    
    # Initialize audit logger
    audit_logger = AuditLogger(
        signing_key_path="audit_signing_key.pem",
        genesis_hash_path="genesis_hash.txt",
        storage_path="audit_events.json"
    )
    
    # Initialize anomaly detector with audit logger
    config = AnomalyDetectionConfig(
        baseline_window_hours=24,
        z_score_threshold=3.0,
        sensitivity="medium",
        monitored_features=["battery_level", "message_frequency", "movement_speed"]
    )
    detector = AnomalyDetector(config=config, audit_logger=audit_logger)
    
    # Simulate normal robot behavior to build baseline
    print("Building baseline with normal robot behavior...")
    for i in range(20):
        normal_metrics = RobotMetrics(
            robot_id="dog1",
            timestamp=time.time(),
            position=(10 + i, 10 + i),
            battery_level=80.0 + (i % 5),  # Normal battery levels
            task_completion_time=5.0,
            message_frequency=10.0,
            movement_speed=1.5
        )
        detector.update_baseline("dog1", normal_metrics)
    
    print(f"Baseline established with {len(detector._baselines['dog1']['battery_level'])} samples")
    
    # Simulate normal behavior (no anomaly)
    print("\nTesting with normal metrics...")
    normal_metrics = RobotMetrics(
        robot_id="dog1",
        timestamp=time.time(),
        position=(30, 30),
        battery_level=82.0,
        task_completion_time=5.0,
        message_frequency=10.0,
        movement_speed=1.5
    )
    
    score, features, alert = detector.detect_and_log_anomaly("dog1", normal_metrics)
    print(f"Normal behavior - Score: {score:.2f}, Features: {features}, Alert: {alert}")
    
    # Simulate anomalous behavior (very low battery)
    print("\nTesting with anomalous metrics (low battery)...")
    anomalous_metrics = RobotMetrics(
        robot_id="dog1",
        timestamp=time.time(),
        position=(31, 31),
        battery_level=5.0,  # Anomalously low!
        task_completion_time=5.0,
        message_frequency=10.0,
        movement_speed=1.5
    )
    
    score, features, alert = detector.detect_and_log_anomaly("dog1", anomalous_metrics)
    print(f"Anomalous behavior - Score: {score:.2f}, Features: {features}, Alert: {alert}")
    
    # Simulate anomalous behavior (high message frequency)
    print("\nTesting with anomalous metrics (high message frequency)...")
    anomalous_metrics2 = RobotMetrics(
        robot_id="dog1",
        timestamp=time.time(),
        position=(32, 32),
        battery_level=80.0,
        task_completion_time=5.0,
        message_frequency=100.0,  # Anomalously high!
        movement_speed=1.5
    )
    
    score, features, alert = detector.detect_and_log_anomaly("dog1", anomalous_metrics2)
    print(f"Anomalous behavior - Score: {score:.2f}, Features: {features}, Alert: {alert}")
    
    # Display audit log summary
    print(f"\n--- Audit Log Summary ---")
    print(f"Total events logged: {audit_logger.get_event_count()}")
    
    # Show anomaly events
    anomaly_events = [
        e for e in audit_logger.events 
        if e.category in ["anomaly_detection", "anomaly_alert"]
    ]
    
    print(f"Anomaly events: {len(anomaly_events)}")
    for event in anomaly_events:
        print(f"\n  Event: {event.title}")
        print(f"  Category: {event.category}")
        print(f"  Robot: {event.actor}")
        print(f"  Score: {event.details['anomaly_score']:.2f}")
        print(f"  Features: {event.details['anomalous_features']}")
        print(f"  Alert Generated: {event.details['alert_generated']}")
    
    # Verify audit chain integrity
    print(f"\n--- Audit Chain Verification ---")
    valid, tampered_index = audit_logger.verify_chain_integrity()
    if valid:
        print(f"✓ Audit chain is valid and untampered")
    else:
        print(f"✗ Audit chain is tampered at index {tampered_index}")


if __name__ == "__main__":
    main()
