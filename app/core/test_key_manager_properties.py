"""
Property-Based Tests for Key Manager

Tests universal correctness properties using hypothesis framework.
Each test validates properties that should hold for all valid inputs.

Requirements: 3.1, 3.2, 3.3, 3.4, 4.1, 4.3, 4.4, 4.5, 5.2, 5.3, 5.4
"""

import os
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from hypothesis import given, settings, strategies as st

from app.core.key_manager import KeyManager, KeyRotationPolicy


# ============================================================================
# Property 1: HKDF Key Derivation Correctness
# ============================================================================

@given(
    session_id=st.text(min_size=1, max_size=64, alphabet=st.characters(blacklist_categories=('Cs',))),
    key_id=st.text(min_size=1, max_size=64, alphabet=st.characters(blacklist_categories=('Cs',)))
)
@settings(max_examples=100)
def test_property_1_hkdf_key_derivation_correctness(session_id, key_id):
    """
    **Property 1: HKDF Key Derivation Correctness**
    
    **Validates: Requirements 3.1, 3.2, 3.3**
    
    For any master key, session_id, and key_id, deriving a session key SHALL 
    use HKDF-SHA256 with session_id as salt, key_id as info parameter, and 
    produce exactly 32 bytes of output.
    """
    # Create temporary key file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
        master_key = os.urandom(32)
        f.write(master_key)
        key_path = f.name
    
    try:
        # Set correct permissions
        os.chmod(key_path, 0o600)
        
        # Initialize key manager
        key_manager = KeyManager(master_key_source=key_path)
        
        # Derive session key
        session_key = key_manager.derive_session_key(session_id, key_id)
        
        # Property: Output is exactly 32 bytes (256 bits)
        assert len(session_key) == 32, f"Expected 32 bytes, got {len(session_key)}"
        assert isinstance(session_key, bytes), f"Expected bytes, got {type(session_key)}"
        
        # Property: Uses HKDF-SHA256 with correct parameters
        # Verify by re-deriving with same parameters
        expected_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_id.encode('utf-8'),
            info=f"LBSE::{key_id}".encode('utf-8'),
        ).derive(master_key)
        
        assert session_key == expected_key, \
            "Derived key does not match HKDF-SHA256 with specified parameters"
        
    finally:
        # Clean up
        if os.path.exists(key_path):
            os.unlink(key_path)


# ============================================================================
# Property 2: Cryptographic Key Independence
# ============================================================================

@given(
    session_id_1=st.text(min_size=1, max_size=64, alphabet=st.characters(blacklist_categories=('Cs',))),
    session_id_2=st.text(min_size=1, max_size=64, alphabet=st.characters(blacklist_categories=('Cs',))),
    key_id=st.text(min_size=1, max_size=64, alphabet=st.characters(blacklist_categories=('Cs',)))
)
@settings(max_examples=100)
def test_property_2_cryptographic_key_independence(session_id_1, session_id_2, key_id):
    """
    **Property 2: Cryptographic Key Independence**
    
    **Validates: Requirement 3.4**
    
    For any master key and any two distinct session_ids, the derived session 
    keys SHALL be cryptographically independent (no statistical correlation).
    """
    # Skip if session_ids are the same
    if session_id_1 == session_id_2:
        return
    
    # Create temporary key file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
        master_key = os.urandom(32)
        f.write(master_key)
        key_path = f.name
    
    try:
        # Set correct permissions
        os.chmod(key_path, 0o600)
        
        # Initialize key manager
        key_manager = KeyManager(master_key_source=key_path)
        
        # Derive two session keys with different session_ids
        key1 = key_manager.derive_session_key(session_id_1, key_id)
        key2 = key_manager.derive_session_key(session_id_2, key_id)
        
        # Property: Keys must be different (cryptographic independence)
        assert key1 != key2, \
            f"Keys derived from different session_ids must be different"
        
        # Property: No obvious bit patterns (basic statistical independence check)
        # XOR the keys - result should not be all zeros or all ones
        xor_result = bytes(a ^ b for a, b in zip(key1, key2))
        assert xor_result != b'\x00' * 32, "Keys are identical (XOR is all zeros)"
        assert xor_result != b'\xff' * 32, "Keys are bitwise inverse (XOR is all ones)"
        
        # Property: Hamming distance should be significant (roughly 50% of bits different)
        # For 256 bits, expect around 128 bits different (allow 64-192 range)
        hamming_distance = sum(bin(byte).count('1') for byte in xor_result)
        assert 64 <= hamming_distance <= 192, \
            f"Hamming distance {hamming_distance} suggests correlation (expected 64-192)"
        
    finally:
        # Clean up
        if os.path.exists(key_path):
            os.unlink(key_path)


# ============================================================================
# Property 3: Robot Key Pair Uniqueness
# ============================================================================

@given(
    robot_id_1=st.text(min_size=1, max_size=32, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd'), 
        min_codepoint=ord('a'), 
        max_codepoint=ord('z')
    ) | st.just('_')),
    robot_id_2=st.text(min_size=1, max_size=32, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd'), 
        min_codepoint=ord('a'), 
        max_codepoint=ord('z')
    ) | st.just('_'))
)
@settings(max_examples=100)
def test_property_3_robot_key_pair_uniqueness(robot_id_1, robot_id_2):
    """
    **Property 3: Robot Key Pair Uniqueness**
    
    **Validates: Requirements 4.1, 4.4**
    
    For any two distinct robot_ids, the generated key pairs SHALL be unique 
    (different public keys and different private keys).
    """
    # Skip if robot_ids are the same
    if robot_id_1 == robot_id_2:
        return
    
    # Create temporary key file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
        f.write(os.urandom(32))
        key_path = f.name
    
    try:
        # Set correct permissions
        os.chmod(key_path, 0o600)
        
        # Initialize key manager
        key_manager = KeyManager(master_key_source=key_path)
        
        # Generate key pairs for two different robots
        pub1, priv1 = key_manager.generate_robot_keypair(robot_id_1)
        pub2, priv2 = key_manager.generate_robot_keypair(robot_id_2)
        
        # Property: Public keys must be different
        assert pub1 != pub2, \
            f"Public keys for different robots must be unique"
        
        # Property: Private keys must be different
        assert priv1 != priv2, \
            f"Private keys for different robots must be unique"
        
        # Property: Keys must be in PEM format
        assert pub1.startswith(b'-----BEGIN PUBLIC KEY-----'), \
            "Public key must be in PEM format"
        assert priv1.startswith(b'-----BEGIN PRIVATE KEY-----'), \
            "Private key must be in PEM format"
        
        # Property: Key pairs must be stored in key manager
        assert robot_id_1 in key_manager.robot_keys
        assert robot_id_2 in key_manager.robot_keys
        
        # Property: Each robot has unique key_id
        key_id_1 = key_manager.robot_keys[robot_id_1].key_id
        key_id_2 = key_manager.robot_keys[robot_id_2].key_id
        assert key_id_1 != key_id_2, \
            f"Each robot must have unique key_id"
        
    finally:
        # Clean up
        if os.path.exists(key_path):
            os.unlink(key_path)


# ============================================================================
# Property 4: Robot Key Revocation Consistency
# ============================================================================

@given(
    robot_id=st.text(min_size=1, max_size=32, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd'), 
        min_codepoint=ord('a'), 
        max_codepoint=ord('z')
    ) | st.just('_'))
)
@settings(max_examples=100)
def test_property_4_robot_key_revocation_consistency(robot_id):
    """
    **Property 4: Robot Key Revocation Consistency**
    
    **Validates: Requirements 4.3, 4.5**
    
    For any robot_id, after revocation, all authentication attempts using that 
    robot's key pair SHALL fail, and the key pair SHALL be marked as invalid 
    in the key manager's state.
    """
    # Create temporary key file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
        f.write(os.urandom(32))
        key_path = f.name
    
    try:
        # Set correct permissions
        os.chmod(key_path, 0o600)
        
        # Initialize key manager
        key_manager = KeyManager(master_key_source=key_path)
        
        # Generate key pair for robot
        pub, priv = key_manager.generate_robot_keypair(robot_id)
        
        # Property: Before revocation, key should not be revoked
        assert not key_manager.is_robot_key_revoked(robot_id), \
            "Newly generated key should not be revoked"
        
        # Revoke the robot's key
        key_manager.revoke_robot_key(robot_id)
        
        # Property: After revocation, key must be marked as revoked
        assert key_manager.is_robot_key_revoked(robot_id), \
            "Revoked key must be marked as revoked in key manager state"
        
        # Property: Revoked flag must be set in stored key pair
        assert key_manager.robot_keys[robot_id].revoked is True, \
            "Revoked flag must be True in stored key pair"
        
        # Property: Revocation is persistent (check again)
        assert key_manager.is_robot_key_revoked(robot_id), \
            "Revocation status must be consistent across multiple checks"
        
    finally:
        # Clean up
        if os.path.exists(key_path):
            os.unlink(key_path)


# ============================================================================
# Property 5: Key Rotation Preservation
# ============================================================================

@given(
    session_id=st.text(min_size=1, max_size=64, alphabet=st.characters(blacklist_categories=('Cs',))),
    key_id=st.text(min_size=1, max_size=64, alphabet=st.characters(blacklist_categories=('Cs',))),
    grace_period_minutes=st.integers(min_value=1, max_value=60)
)
@settings(max_examples=100, deadline=None)
def test_property_5_key_rotation_preservation(session_id, key_id, grace_period_minutes):
    """
    **Property 5: Key Rotation Preservation**
    
    **Validates: Requirements 5.2, 5.3, 5.4**
    
    For any session with an active session key, when key rotation occurs, the 
    old key SHALL remain valid for the grace period duration, and a new key 
    SHALL be generated and logged to the audit system.
    """
    # Create temporary key file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
        f.write(os.urandom(32))
        key_path = f.name
    
    try:
        # Set correct permissions
        os.chmod(key_path, 0o600)
        
        # Initialize key manager with custom rotation policy
        rotation_policy = KeyRotationPolicy(
            rotation_interval_hours=1,
            grace_period_minutes=grace_period_minutes,
            auto_rotate_master_key=False
        )
        key_manager = KeyManager(
            master_key_source=key_path,
            rotation_policy=rotation_policy
        )
        
        # Derive initial session key
        old_key = key_manager.derive_session_key(session_id, key_id)
        
        # Property: Old key is valid before rotation
        assert key_manager.is_key_in_grace_period(session_id, old_key), \
            "Old key should be valid before rotation"
        
        # Rotate the session key
        new_key = key_manager.rotate_session_key(session_id)
        
        # Property: New key must be different from old key
        assert new_key != old_key, \
            "Rotated key must be different from old key"
        
        # Property: New key is the current session key
        assert key_manager.session_keys[session_id].session_key == new_key, \
            "New key must be stored as current session key"
        
        # Property: Old key is stored as previous key
        assert key_manager.session_keys[session_id].previous_key == old_key, \
            "Old key must be stored as previous key"
        
        # Property: Both old and new keys are valid during grace period
        assert key_manager.is_key_in_grace_period(session_id, old_key), \
            "Old key must remain valid during grace period"
        assert key_manager.is_key_in_grace_period(session_id, new_key), \
            "New key must be valid immediately after rotation"
        
        # Property: Grace period expiration time is set correctly
        now = time.time()
        expected_expiry = now + (grace_period_minutes * 60)
        actual_expiry = key_manager.session_keys[session_id].previous_key_expires_at
        
        # Allow 2 second tolerance for test execution time
        assert abs(actual_expiry - expected_expiry) < 2, \
            f"Grace period expiry time incorrect: expected ~{expected_expiry}, got {actual_expiry}"
        
    finally:
        # Clean up
        if os.path.exists(key_path):
            os.unlink(key_path)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
