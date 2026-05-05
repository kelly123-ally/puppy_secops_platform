"""
Test script to verify blocked attacks are correctly counted in Security Dashboard.

This script:
1. Triggers various attack types through the simulator
2. Queries the Security Dashboard API
3. Verifies that blocked attacks are correctly counted
"""

import requests
import time
import json

BASE_URL = "http://127.0.0.1:8000"

def login():
    """Login as admin to get session."""
    response = requests.post(
        f"{BASE_URL}/api/login",
        json={"username": "admin", "password": "Admin123!"},
        allow_redirects=False
    )
    if response.status_code in [200, 302, 303]:
        # Extract session cookie
        cookies = response.cookies
        print("✓ Logged in successfully")
        return cookies
    else:
        print(f"✗ Login failed: {response.status_code}")
        print(f"  Response: {response.text}")
        return None

def get_current_metrics(cookies):
    """Get current security metrics from dashboard API."""
    response = requests.get(
        f"{BASE_URL}/api/dashboard/metrics/summary",
        cookies=cookies
    )
    if response.status_code == 200:
        return response.json()
    else:
        print(f"✗ Failed to get metrics: {response.status_code}")
        return None

def trigger_unsigned_injection(cookies):
    """Trigger an unsigned injection attack."""
    task_data = {
        "task_id": f"attack_test_{int(time.time())}",
        "site": "zone_a",
        "x": 10,
        "y": 10,
        "priority": 5,
        "cargo_type": "supply",
        "note": "Test attack"
    }
    response = requests.post(
        f"{BASE_URL}/api/attacks/unsigned_injection",
        json=task_data,
        cookies=cookies
    )
    print(f"  Unsigned injection attack: {response.status_code}")
    return response.status_code

def trigger_replay_attack(cookies):
    """Trigger a replay attack."""
    task_data = {
        "task_id": f"replay_test_{int(time.time())}",
        "site": "zone_b",
        "x": 15,
        "y": 15,
        "priority": 3,
        "cargo_type": "medical",
        "note": "Replay test"
    }
    response = requests.post(
        f"{BASE_URL}/api/attacks/replay",
        json=task_data,
        cookies=cookies
    )
    print(f"  Replay attack: {response.status_code}")
    return response.status_code

def trigger_heartbeat_spoof(cookies):
    """Trigger a heartbeat spoof attack."""
    response = requests.post(
        f"{BASE_URL}/api/attacks/heartbeat_spoof",
        json={"robot_id": "dog1"},
        cookies=cookies
    )
    print(f"  Heartbeat spoof attack: {response.status_code}")
    return response.status_code

def main():
    print("=" * 60)
    print("Testing Blocked Attacks Fix")
    print("=" * 60)
    
    # Step 1: Login
    print("\n[1] Logging in...")
    cookies = login()
    if not cookies:
        print("Cannot proceed without login")
        return
    
    # Step 2: Get initial metrics
    print("\n[2] Getting initial metrics...")
    initial_metrics = get_current_metrics(cookies)
    if initial_metrics:
        initial_blocked = initial_metrics.get("total_blocked_attacks", 0)
        initial_by_type = initial_metrics.get("blocked_attacks_by_type", {})
        print(f"  Initial blocked attacks: {initial_blocked}")
        print(f"  By type: {json.dumps(initial_by_type, indent=4)}")
    else:
        print("  Could not get initial metrics")
        initial_blocked = 0
        initial_by_type = {}
    
    # Step 3: Trigger attacks
    print("\n[3] Triggering attacks...")
    trigger_unsigned_injection(cookies)
    time.sleep(0.5)
    
    trigger_replay_attack(cookies)
    time.sleep(0.5)
    
    trigger_heartbeat_spoof(cookies)
    time.sleep(0.5)
    
    # Step 4: Wait for metrics to update
    print("\n[4] Waiting for metrics to update (6 seconds)...")
    time.sleep(6)
    
    # Step 5: Get updated metrics
    print("\n[5] Getting updated metrics...")
    updated_metrics = get_current_metrics(cookies)
    if updated_metrics:
        updated_blocked = updated_metrics.get("total_blocked_attacks", 0)
        updated_by_type = updated_metrics.get("blocked_attacks_by_type", {})
        print(f"  Updated blocked attacks: {updated_blocked}")
        print(f"  By type: {json.dumps(updated_by_type, indent=4)}")
    else:
        print("  Could not get updated metrics")
        updated_blocked = 0
        updated_by_type = {}
    
    # Step 6: Verify results
    print("\n[6] Verification Results:")
    print("=" * 60)
    
    if updated_blocked > initial_blocked:
        increase = updated_blocked - initial_blocked
        print(f"✓ SUCCESS: Blocked attacks increased by {increase}")
        print(f"  Before: {initial_blocked}")
        print(f"  After:  {updated_blocked}")
        
        # Show breakdown
        print("\n  Attack type breakdown:")
        for attack_type, count in updated_by_type.items():
            initial_count = initial_by_type.get(attack_type, 0)
            if count > initial_count:
                print(f"    {attack_type}: {initial_count} → {count} (+{count - initial_count})")
            else:
                print(f"    {attack_type}: {count}")
        
        print("\n✓ Fix is working correctly!")
    else:
        print(f"✗ FAILED: Blocked attacks did not increase")
        print(f"  Before: {initial_blocked}")
        print(f"  After:  {updated_blocked}")
        print("\n  Possible issues:")
        print("  - Metrics collection interval not reached")
        print("  - Audit logger not recording events")
        print("  - Dashboard API not querying correctly")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
