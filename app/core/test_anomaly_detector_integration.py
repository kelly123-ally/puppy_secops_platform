"""
Unit tests for Anomaly Detector integration with Audit Logger

Tests the integration between AnomalyDetector and AuditLogger to validate
Requirement 17.6: Log anomaly detections with robot_id, score, and anomalous features
"""

import pytest
import time
from app.core.anomaly_detector import (
    AnomalyDetector,
    AnomalyDetectionConfig,
    RobotMetrics
)
from app.core.audit_logger import AuditLogger


@pytest.fixture
def audit_logger(tmp_path):
    """Create a temporary audit logger for testing."""
    signing_key_path = str(tmp_path / "test_signing_key.pem")
    genesis_hash_path = str(tmp_path / "test_genesis_hash.txt")
    storage_path = str(tmp_path / "test_audit_events.json")
    
    return AuditLogger(
        signing_key_path=signing_key_path,
        genesis_hash_path=genesis_hash_path,
        storage_path=storage_path
    )


@pytest.fixture
def anomaly_detector(audit_logger):
    """Create anomaly detector with audit logger integration."""
    config = AnomalyDetectionConfig(
        baseline_window_hours=24,
        z_score_threshold=3.0,
        sensitivity="medium",
        monitored_features=["battery_level", "message_frequency", "movement_speed"]
    )
    return AnomalyDetector(config=config, audit_logger=audit_logger)


@pytest.fixture
def normal_metrics():
    """Create normal robot metrics for baseline."""
    return RobotMetrics(
        robot_id="dog1",
        timestamp=time.time(),
        position=(10, 10),
        battery_level=80.0,
        task_completion_time=5.0,
        message_frequency=10.0,
        movement_speed=1.5
    )


@pytest.fixture
def anomalous_metrics():
    """Create anomalous robot metrics (very low battery)."""
    return RobotMetrics(
        robot_id="dog1",
        timestamp=time.time(),
        position=(10, 10),
        battery_level=5.0,  # Anomalously low
        task_completion_time=5.0,
        message_frequency=10.0,
        movement_speed=1.5
    )


class TestAnomalyDetectorAuditIntegration:
    """Test suite for anomaly detector and audit logger integration."""
    
    def test_detect_and_log_anomaly_logs_to_audit_logger(
        self, 
        anomaly_detector, 
        audit_logger, 
        normal_metrics,
        anomalous_metrics
    ):
        """
        Test that anomaly detections are logged to the audit logger.
        
        Validates Requirement 17.6: Log the event with the Anomaly_Score to the Audit_Logger
        """
        # Build baseline with normal metrics
        for _ in range(10):
            anomaly_detector.update_baseline("dog1", normal_metrics)
        
        # Detect anomaly with anomalous metrics
        score, features, alert_generated = anomaly_detector.detect_and_log_anomaly(
            "dog1", 
            anomalous_metrics
        )
        
        # Verify anomaly was detected
        assert score > 0, "Anomaly score should be greater than 0"
        
        # Verify audit log was created
        assert audit_logger.get_event_count() > 0, "Audit event should be logged"
        
        # Get the logged event
        events = audit_logger.events
        assert len(events) > 0, "At least one event should be logged"
        
        last_event = events[-1]
        
        # Verify event contains required information
        assert last_event.actor == "dog1", "Event actor should be robot_id"
        assert "anomaly_score" in last_event.details, "Event should contain anomaly_score"
        assert "anomalous_features" in last_event.details, "Event should contain anomalous_features"
        assert "robot_id" in last_event.details, "Event should contain robot_id"
        
        # Verify anomaly score is logged correctly
        assert last_event.details["anomaly_score"] == score, "Logged score should match detected score"
        assert last_event.details["anomalous_features"] == features, "Logged features should match detected features"
    
    def test_detect_and_log_anomaly_generates_alert_when_threshold_exceeded(
        self, 
        anomaly_detector, 
        audit_logger, 
        normal_metrics,
        anomalous_metrics
    ):
        """
        Test that alerts are generated when anomaly score exceeds threshold.
        
        Validates Requirement 17.3: Generate alerts when score exceeds threshold
        """
        # Build baseline with normal metrics
        for _ in range(10):
            anomaly_detector.update_baseline("dog1", normal_metrics)
        
        # Detect anomaly with anomalous metrics
        score, features, alert_generated = anomaly_detector.detect_and_log_anomaly(
            "dog1", 
            anomalous_metrics
        )
        
        # Verify alert was generated if score exceeds threshold
        if score > anomaly_detector.config.z_score_threshold:
            assert alert_generated, "Alert should be generated when score exceeds threshold"
            
            # Verify audit log category indicates alert
            last_event = audit_logger.events[-1]
            assert last_event.category == "anomaly_alert", "Event category should be anomaly_alert"
            assert "alert" in last_event.title.lower(), "Event title should mention alert"
        else:
            assert not alert_generated, "Alert should not be generated when score is below threshold"
    
    def test_detect_and_log_anomaly_includes_robot_metrics(
        self, 
        anomaly_detector, 
        audit_logger, 
        normal_metrics,
        anomalous_metrics
    ):
        """
        Test that logged anomaly events include robot metrics.
        
        Validates Requirement 17.6: Log the event with robot_id, score, and anomalous features
        """
        # Build baseline
        for _ in range(10):
            anomaly_detector.update_baseline("dog1", normal_metrics)
        
        # Detect anomaly
        score, features, alert_generated = anomaly_detector.detect_and_log_anomaly(
            "dog1", 
            anomalous_metrics
        )
        
        # Get logged event
        last_event = audit_logger.events[-1]
        
        # Verify metrics are included in details
        assert "metrics" in last_event.details, "Event should contain metrics"
        metrics_data = last_event.details["metrics"]
        
        assert "battery_level" in metrics_data, "Metrics should include battery_level"
        assert "message_frequency" in metrics_data, "Metrics should include message_frequency"
        assert "movement_speed" in metrics_data, "Metrics should include movement_speed"
        assert "timestamp" in metrics_data, "Metrics should include timestamp"
        assert "position" in metrics_data, "Metrics should include position"
    
    def test_detect_and_log_anomaly_without_audit_logger(self, normal_metrics, anomalous_metrics):
        """
        Test that anomaly detection works without audit logger (graceful degradation).
        """
        # Create detector without audit logger
        config = AnomalyDetectionConfig(
            baseline_window_hours=24,
            z_score_threshold=3.0,
            sensitivity="medium"
        )
        detector = AnomalyDetector(config=config, audit_logger=None)
        
        # Build baseline
        for _ in range(10):
            detector.update_baseline("dog1", normal_metrics)
        
        # Detect anomaly should work without audit logger
        score, features, alert_generated = detector.detect_and_log_anomaly(
            "dog1", 
            anomalous_metrics
        )
        
        # Verify detection still works
        assert score >= 0, "Anomaly detection should work without audit logger"
    
    def test_detect_and_log_anomaly_no_baseline(self, anomaly_detector, audit_logger, normal_metrics):
        """
        Test that no audit event is logged when there's no baseline (score = 0).
        """
        initial_event_count = audit_logger.get_event_count()
        
        # Detect anomaly without baseline
        score, features, alert_generated = anomaly_detector.detect_and_log_anomaly(
            "dog1", 
            normal_metrics
        )
        
        # Verify no anomaly detected
        assert score == 0.0, "Score should be 0 without baseline"
        assert not alert_generated, "No alert should be generated without baseline"
        
        # Verify no audit event was logged (score = 0)
        assert audit_logger.get_event_count() == initial_event_count, "No audit event should be logged when score is 0"
    
    def test_detect_and_log_anomaly_includes_threshold_in_details(
        self, 
        anomaly_detector, 
        audit_logger, 
        normal_metrics,
        anomalous_metrics
    ):
        """
        Test that logged events include the threshold for context.
        """
        # Build baseline
        for _ in range(10):
            anomaly_detector.update_baseline("dog1", normal_metrics)
        
        # Detect anomaly
        score, features, alert_generated = anomaly_detector.detect_and_log_anomaly(
            "dog1", 
            anomalous_metrics
        )
        
        # Get logged event
        last_event = audit_logger.events[-1]
        
        # Verify threshold is included
        assert "threshold" in last_event.details, "Event should contain threshold"
        assert last_event.details["threshold"] == anomaly_detector.config.z_score_threshold
        
        # Verify alert_generated flag is included
        assert "alert_generated" in last_event.details, "Event should contain alert_generated flag"
        assert last_event.details["alert_generated"] == alert_generated
    
    def test_detect_and_log_anomaly_multiple_robots(
        self, 
        anomaly_detector, 
        audit_logger, 
        normal_metrics,
        anomalous_metrics
    ):
        """
        Test that anomaly detection and logging works for multiple robots.
        """
        # Build baseline for dog1
        for _ in range(10):
            anomaly_detector.update_baseline("dog1", normal_metrics)
        
        # Build baseline for dog2
        dog2_metrics = RobotMetrics(
            robot_id="dog2",
            timestamp=time.time(),
            position=(20, 20),
            battery_level=85.0,
            task_completion_time=4.5,
            message_frequency=12.0,
            movement_speed=1.8
        )
        for _ in range(10):
            anomaly_detector.update_baseline("dog2", dog2_metrics)
        
        # Detect anomaly for dog1
        score1, features1, alert1 = anomaly_detector.detect_and_log_anomaly(
            "dog1", 
            anomalous_metrics
        )
        
        # Detect anomaly for dog2 (normal)
        score2, features2, alert2 = anomaly_detector.detect_and_log_anomaly(
            "dog2", 
            dog2_metrics
        )
        
        # Verify both events are logged
        assert audit_logger.get_event_count() >= 1, "At least one event should be logged"
        
        # Verify events are for correct robots
        events = audit_logger.events
        robot_ids = [event.actor for event in events]
        
        if score1 > 0:
            assert "dog1" in robot_ids, "dog1 event should be logged"
        
        # dog2 should not have an event if score is 0
        if score2 == 0:
            # Count dog2 events
            dog2_events = [e for e in events if e.actor == "dog2"]
            assert len(dog2_events) == 0, "dog2 should not have events when score is 0"


class TestAnomalyDetectorBackwardCompatibility:
    """Test that existing detect_anomaly method still works without audit logger."""
    
    def test_detect_anomaly_without_audit_logger(self, normal_metrics, anomalous_metrics):
        """
        Test that the original detect_anomaly method works without audit logger.
        """
        config = AnomalyDetectionConfig(
            baseline_window_hours=24,
            z_score_threshold=3.0,
            sensitivity="medium"
        )
        detector = AnomalyDetector(config=config, audit_logger=None)
        
        # Build baseline
        for _ in range(10):
            detector.update_baseline("dog1", normal_metrics)
        
        # Use original detect_anomaly method
        score, features = detector.detect_anomaly("dog1", anomalous_metrics)
        
        # Verify it still works
        assert score >= 0, "Original detect_anomaly should still work"
        assert isinstance(features, list), "Features should be a list"
