"""
Anomaly Detection Module for Robot Behavior Monitoring

This module implements statistical anomaly detection for robot behavior metrics
to identify compromised or malfunctioning robots in the fleet.

Validates Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
import statistics
import math

if TYPE_CHECKING:
    from app.core.audit_logger import AuditLogger


@dataclass
class RobotMetrics:
    """Robot behavior metrics for anomaly detection."""
    robot_id: str
    timestamp: float
    position: Tuple[int, int]
    battery_level: float
    task_completion_time: Optional[float]
    message_frequency: float  # Messages per minute
    movement_speed: float


@dataclass
class AnomalyDetectionConfig:
    """Configuration for anomaly detection behavior."""
    baseline_window_hours: int = 24  # Hours of data for baseline
    z_score_threshold: float = 3.0   # Standard deviations for anomaly
    sensitivity: str = "medium"      # low, medium, high
    monitored_features: List[str] = field(default_factory=lambda: [
        "battery_level",
        "task_completion_time",
        "message_frequency",
        "movement_speed"
    ])


class AnomalyDetector:
    """
    Detects anomalous robot behavior using statistical methods.
    
    Monitors robot behavior metrics and computes anomaly scores based on
    deviation from learned baseline behavior. Supports configurable sensitivity
    levels and tracks multiple behavioral features.
    
    Validates Requirements:
    - 17.1: Monitor movement patterns, task completion times, battery consumption, message frequency
    - 17.2: Compute anomaly score when behavior deviates from baseline
    - 17.3: Generate alerts when score exceeds threshold (handled by caller)
    - 17.4: Learn baseline behavior from historical data
    - 17.5: Support configurable sensitivity levels
    """
    
    def __init__(self, config: AnomalyDetectionConfig, audit_logger: Optional['AuditLogger'] = None):
        """
        Initialize anomaly detector with configuration.
        
        Args:
            config: Configuration specifying thresholds and monitored features
            audit_logger: Optional audit logger for logging anomaly detections (Requirement 17.6)
        """
        self.config = config
        self.audit_logger = audit_logger
        
        # Baseline storage: robot_id -> feature -> list of historical values
        self._baselines: Dict[str, Dict[str, List[float]]] = {}
        
        # Sensitivity level mappings to z-score thresholds
        self._sensitivity_thresholds = {
            "low": 4.0,      # Less sensitive, fewer false positives
            "medium": 3.0,   # Balanced
            "high": 2.0      # More sensitive, more false positives
        }
        
        # Update threshold based on initial sensitivity
        self._update_threshold()
    
    def _update_threshold(self) -> None:
        """Update z-score threshold based on current sensitivity level."""
        self.config.z_score_threshold = self._sensitivity_thresholds.get(
            self.config.sensitivity, 
            3.0  # Default to medium
        )
    
    def update_baseline(self, robot_id: str, metrics: RobotMetrics) -> None:
        """
        Update baseline behavior model with new robot metrics.
        
        Learns normal behavior from historical data by maintaining a sliding
        window of recent metric values for each robot.
        
        Validates Requirement 17.4: Learn baseline behavior from historical data
        
        Args:
            robot_id: Identifier of the robot
            metrics: Current behavior metrics to add to baseline
        """
        # Initialize baseline storage for new robot
        if robot_id not in self._baselines:
            self._baselines[robot_id] = {
                feature: [] for feature in self.config.monitored_features
            }
        
        baseline = self._baselines[robot_id]
        
        # Add metrics to baseline for each monitored feature
        if "battery_level" in self.config.monitored_features:
            baseline["battery_level"].append(metrics.battery_level)
        
        if "task_completion_time" in self.config.monitored_features:
            if metrics.task_completion_time is not None:
                baseline["task_completion_time"].append(metrics.task_completion_time)
        
        if "message_frequency" in self.config.monitored_features:
            baseline["message_frequency"].append(metrics.message_frequency)
        
        if "movement_speed" in self.config.monitored_features:
            baseline["movement_speed"].append(metrics.movement_speed)
        
        # Maintain sliding window (limit history size)
        # Approximate: 1 sample per minute * 60 minutes * baseline_window_hours
        max_samples = 60 * self.config.baseline_window_hours
        for feature in baseline:
            if len(baseline[feature]) > max_samples:
                baseline[feature] = baseline[feature][-max_samples:]
    
    def detect_anomaly(
        self, 
        robot_id: str, 
        metrics: RobotMetrics
    ) -> Tuple[float, List[str]]:
        """
        Compute anomaly score and identify anomalous features.
        
        Uses z-score statistical method to detect deviations from baseline.
        The anomaly score is the maximum z-score across all monitored features.
        
        Validates Requirements:
        - 17.1: Monitor movement patterns, task completion times, battery consumption, message frequency
        - 17.2: Compute anomaly score when behavior deviates from baseline
        
        Args:
            robot_id: Identifier of the robot
            metrics: Current behavior metrics to evaluate
        
        Returns:
            Tuple of (anomaly_score, list_of_anomalous_features)
            - anomaly_score: Maximum z-score across all features (0.0 if no baseline)
            - anomalous_features: List of feature names exceeding threshold
        """
        # No baseline yet - cannot detect anomalies
        if robot_id not in self._baselines:
            return (0.0, [])
        
        baseline = self._baselines[robot_id]
        anomalous_features: List[str] = []
        max_z_score = 0.0
        
        # Compute z-score for each monitored feature
        feature_z_scores: Dict[str, float] = {}
        
        if "battery_level" in self.config.monitored_features:
            z_score = self._compute_z_score(
                baseline["battery_level"], 
                metrics.battery_level
            )
            if z_score is not None:
                feature_z_scores["battery_level"] = z_score
                max_z_score = max(max_z_score, z_score)
                if z_score > self.config.z_score_threshold:
                    anomalous_features.append("battery_level")
        
        if "task_completion_time" in self.config.monitored_features:
            if metrics.task_completion_time is not None:
                z_score = self._compute_z_score(
                    baseline["task_completion_time"],
                    metrics.task_completion_time
                )
                if z_score is not None:
                    feature_z_scores["task_completion_time"] = z_score
                    max_z_score = max(max_z_score, z_score)
                    if z_score > self.config.z_score_threshold:
                        anomalous_features.append("task_completion_time")
        
        if "message_frequency" in self.config.monitored_features:
            z_score = self._compute_z_score(
                baseline["message_frequency"],
                metrics.message_frequency
            )
            if z_score is not None:
                feature_z_scores["message_frequency"] = z_score
                max_z_score = max(max_z_score, z_score)
                if z_score > self.config.z_score_threshold:
                    anomalous_features.append("message_frequency")
        
        if "movement_speed" in self.config.monitored_features:
            z_score = self._compute_z_score(
                baseline["movement_speed"],
                metrics.movement_speed
            )
            if z_score is not None:
                feature_z_scores["movement_speed"] = z_score
                max_z_score = max(max_z_score, z_score)
                if z_score > self.config.z_score_threshold:
                    anomalous_features.append("movement_speed")
        
        return (max_z_score, anomalous_features)
    
    def _compute_z_score(
        self, 
        baseline_values: List[float], 
        current_value: float
    ) -> Optional[float]:
        """
        Compute z-score for a single feature.
        
        Z-score = (current_value - mean) / standard_deviation
        
        Args:
            baseline_values: Historical values for the feature
            current_value: Current value to evaluate
        
        Returns:
            Z-score (absolute value) or None if insufficient data
        """
        # Need at least 2 samples to compute standard deviation
        if len(baseline_values) < 2:
            return None
        
        mean = statistics.mean(baseline_values)
        stdev = statistics.stdev(baseline_values)
        
        # Avoid division by zero (constant baseline)
        if stdev == 0:
            return 0.0 if current_value == mean else float('inf')
        
        # Return absolute z-score (deviation in either direction is anomalous)
        z_score = abs((current_value - mean) / stdev)
        return z_score
    
    def set_sensitivity(self, level: str) -> None:
        """
        Set detection sensitivity level.
        
        Validates Requirement 17.5: Support configurable sensitivity levels
        
        Args:
            level: Sensitivity level - "low", "medium", or "high"
        
        Raises:
            ValueError: If level is not one of the valid options
        """
        valid_levels = ["low", "medium", "high"]
        if level not in valid_levels:
            raise ValueError(
                f"Invalid sensitivity level: {level}. "
                f"Must be one of {valid_levels}"
            )
        
        self.config.sensitivity = level
        self._update_threshold()
    
    def detect_and_log_anomaly(
        self, 
        robot_id: str, 
        metrics: RobotMetrics
    ) -> Tuple[float, List[str], bool]:
        """
        Detect anomaly, log to audit logger, and generate alert if threshold exceeded.
        
        This method combines anomaly detection with audit logging and alert generation
        to satisfy Requirement 17.6: "WHEN an anomaly is detected, THE Platform SHALL 
        log the event with the Anomaly_Score to the Audit_Logger"
        
        Validates Requirements:
        - 17.2: Compute anomaly score when behavior deviates from baseline
        - 17.3: Generate alerts when score exceeds threshold
        - 17.6: Log the event with the Anomaly_Score to the Audit_Logger
        
        Args:
            robot_id: Identifier of the robot
            metrics: Current behavior metrics to evaluate
        
        Returns:
            Tuple of (anomaly_score, anomalous_features, alert_generated)
            - anomaly_score: Maximum z-score across all features
            - anomalous_features: List of feature names exceeding threshold
            - alert_generated: True if score exceeded threshold and alert was generated
        """
        # Detect anomaly using existing logic
        anomaly_score, anomalous_features = self.detect_anomaly(robot_id, metrics)
        
        # Determine if alert should be generated (score exceeds threshold)
        alert_generated = anomaly_score > self.config.z_score_threshold
        
        # Log to audit logger if anomaly detected (score > 0) and logger is available
        if anomaly_score > 0 and self.audit_logger is not None:
            # Prepare details for audit log
            details = {
                "robot_id": robot_id,
                "anomaly_score": anomaly_score,
                "anomalous_features": anomalous_features,
                "threshold": self.config.z_score_threshold,
                "alert_generated": alert_generated,
                "metrics": {
                    "timestamp": metrics.timestamp,
                    "position": metrics.position,
                    "battery_level": metrics.battery_level,
                    "task_completion_time": metrics.task_completion_time,
                    "message_frequency": metrics.message_frequency,
                    "movement_speed": metrics.movement_speed
                }
            }
            
            # Determine category and title based on alert status
            if alert_generated:
                category = "anomaly_alert"
                title = f"Anomaly alert for robot {robot_id}"
            else:
                category = "anomaly_detection"
                title = f"Anomaly detected for robot {robot_id}"
            
            # Log the anomaly detection event
            self.audit_logger.log_event(
                category=category,
                title=title,
                actor=robot_id,
                details=details
            )
        
        return (anomaly_score, anomalous_features, alert_generated)
