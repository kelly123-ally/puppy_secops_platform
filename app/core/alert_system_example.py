"""
Example usage of AlertSystem

Demonstrates how to use the AlertSystem for real-time security alerting.
"""

import asyncio
from app.core.alert_system import AlertSystem, AlertRule, CRITICAL_EVENTS_RULE
from app.core.audit_logger import AuditLogger


async def main():
    """Example usage of AlertSystem."""
    
    # Initialize audit logger
    audit_logger = AuditLogger(
        signing_key_path="audit_signing_key.pem",
        genesis_hash_path="genesis_hash.txt",
        storage_path="audit_events.json"
    )
    
    # Initialize alert system
    alert_system = AlertSystem(audit_logger=audit_logger)
    
    # Add alert rules
    alert_system.add_alert_rule(CRITICAL_EVENTS_RULE)
    
    # Add custom rule for anomaly detection
    anomaly_rule = AlertRule(
        rule_id="anomaly_medium",
        category="anomaly",
        severity_threshold="medium",
        enabled=True,
        description="Alert on medium and above anomalies"
    )
    alert_system.add_alert_rule(anomaly_rule)
    
    # Generate some example alerts
    print("Generating alerts...")
    
    # Critical certificate revocation
    alert_id1 = await alert_system.generate_alert(
        severity="critical",
        category="cert_revocation",
        subject="dog1",
        title="Robot certificate revoked",
        details={
            "reason": "Anomaly score exceeded threshold",
            "anomaly_score": 8.5,
            "robot_id": "dog1"
        }
    )
    print(f"Generated alert: {alert_id1}")
    
    # High severity authentication failure
    alert_id2 = await alert_system.generate_alert(
        severity="high",
        category="auth_failure_repeated",
        subject="user_attacker",
        title="Repeated authentication failures detected",
        details={
            "ip_address": "192.168.1.100",
            "attempt_count": 10,
            "time_window": "5 minutes"
        }
    )
    print(f"Generated alert: {alert_id2}")
    
    # Medium severity anomaly
    alert_id3 = await alert_system.generate_alert(
        severity="medium",
        category="anomaly",
        subject="dog2",
        title="Anomalous robot behavior detected",
        details={
            "anomaly_score": 4.2,
            "anomalous_features": ["battery_level", "movement_speed"],
            "robot_id": "dog2"
        }
    )
    print(f"Generated alert: {alert_id3}")
    
    # Get alert statistics
    print(f"\nTotal alerts: {alert_system.get_alert_count()}")
    print(f"Alerts by severity: {alert_system.get_alert_count_by_severity()}")
    print(f"Alerts by category: {alert_system.get_alert_count_by_category()}")
    
    # Get recent critical alerts
    critical_alerts = alert_system.get_alert_history(severity="critical")
    print(f"\nCritical alerts: {len(critical_alerts)}")
    for alert in critical_alerts:
        print(f"  - {alert.title} (subject: {alert.subject})")
    
    # Verify audit logging
    audit_events = audit_logger.get_events_by_category("security_alert")
    print(f"\nAudit events logged: {len(audit_events)}")
    
    # Verify chain integrity
    valid, tampered_index = audit_logger.verify_chain_integrity()
    print(f"Audit chain valid: {valid}")


if __name__ == "__main__":
    asyncio.run(main())
