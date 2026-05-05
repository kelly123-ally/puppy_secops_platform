"""
Unit Tests for Key Manager

Tests specific examples and edge cases for key management functionality.

Requirements: 2.1-2.6, 3.1-3.5, 4.1-4.5, 5.1-5.6, 25.1, 25.3, 26.2
"""

import os
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from app.core.key_manager import KeyManager, KeyRotationPolicy, RobotKeyPair


class TestMasterKeyLoading:
    """Test master key loading with correct/incorrect permissions."""
    
    def test_load_master_key_with_correct_permissions(self):
        """Test loading master key from file with 0600 permissions."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            master_key = os.urandom(32)
            f.write(master_key)
            key_path = f.name
        
        try:
            # Set correct permissions
            os.chmod(key_path, 0o600)
            
            # Should load successfully
            key_manager = KeyManager(master_key_source=key_path)
            assert key_manager.master_key == master_key
        finally:
            os.unlink(key_path)
    
    def test_load_master_key_with_incorrect_permissions(self):
        """Test that loading fails with incorrect file permissions (Unix only)."""
        import platform
        if platform.system() == 'Windows':
            pytest.skip("Permission checks not enforced on Windows")
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            # Set incorrect permissions (world-readable)
            os.chmod(key_path, 0o644)
            
            # Should raise PermissionError
            with pytest.raises(PermissionError, match="incorrect permissions"):
                KeyManager(master_key_source=key_path)
        finally:
            os.unlink(key_path)
    
    def test_load_master_key_from_environment_variable(self):
        """Test loading master key from environment variable."""
        master_key = os.urandom(32)
        master_key_hex = master_key.hex()
        
        # Set environment variable
        os.environ['TEST_MASTER_KEY'] = master_key_hex
        
        try:
            key_manager = KeyManager(master_key_source='env:TEST_MASTER_KEY')
            assert key_manager.master_key == master_key
        finally:
            del os.environ['TEST_MASTER_KEY']
    
    def test_generate_master_key_when_missing(self):
        """Test that a new master key is generated when file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / 'new_master.key'
            
            # Key file doesn't exist yet
            assert not key_path.exists()
            
            # Should generate new key
            key_manager = KeyManager(master_key_source=str(key_path))
            
            # Key file should now exist with correct permissions (Unix only)
            assert key_path.exists()
            
            import platform
            if platform.system() != 'Windows':
                stat_info = key_path.stat()
                file_mode = stat_info.st_mode & 0o777
                assert file_mode == 0o600
            
            # Key should be 32 bytes
            assert len(key_manager.master_key) == 32
    
    def test_master_key_wrong_size(self):
        """Test that loading fails if key file has wrong size."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            # Write wrong size key (16 bytes instead of 32)
            f.write(os.urandom(16))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            
            with pytest.raises(ValueError, match="exactly 32 bytes"):
                KeyManager(master_key_source=key_path)
        finally:
            os.unlink(key_path)


class TestKeyGeneration:
    """Test key generation and derivation."""
    
    def test_derive_session_key_produces_32_bytes(self):
        """Test that derived session keys are exactly 32 bytes."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            session_key = key_manager.derive_session_key('session1', 'key1')
            assert len(session_key) == 32
            assert isinstance(session_key, bytes)
        finally:
            os.unlink(key_path)
    
    def test_derive_session_key_is_deterministic(self):
        """Test that same inputs produce same session key."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            key1 = key_manager.derive_session_key('session1', 'key1')
            key2 = key_manager.derive_session_key('session1', 'key1')
            
            # Same inputs should produce same key
            assert key1 == key2
        finally:
            os.unlink(key_path)
    
    def test_robot_keypair_generation(self):
        """Test robot key pair generation."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            pub, priv = key_manager.generate_robot_keypair('robot1')
            
            # Check PEM format
            assert pub.startswith(b'-----BEGIN PUBLIC KEY-----')
            assert priv.startswith(b'-----BEGIN PRIVATE KEY-----')
            
            # Check stored in key manager
            assert 'robot1' in key_manager.robot_keys
            assert key_manager.robot_keys['robot1'].public_key == pub
            assert key_manager.robot_keys['robot1'].private_key == priv
        finally:
            os.unlink(key_path)


class TestKeyRevocation:
    """Test key revocation functionality."""
    
    def test_revoke_robot_key(self):
        """Test revoking a robot's key pair."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            # Generate key pair
            key_manager.generate_robot_keypair('robot1')
            
            # Should not be revoked initially
            assert not key_manager.is_robot_key_revoked('robot1')
            
            # Revoke key
            key_manager.revoke_robot_key('robot1')
            
            # Should now be revoked
            assert key_manager.is_robot_key_revoked('robot1')
            assert key_manager.robot_keys['robot1'].revoked is True
        finally:
            os.unlink(key_path)
    
    def test_revoke_nonexistent_robot_key(self):
        """Test that revoking nonexistent robot raises error."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            with pytest.raises(KeyError, match="not found"):
                key_manager.revoke_robot_key('nonexistent')
        finally:
            os.unlink(key_path)
    
    def test_unknown_robot_is_considered_revoked(self):
        """Test that unknown robots are considered revoked."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            # Unknown robot should be considered revoked
            assert key_manager.is_robot_key_revoked('unknown_robot')
        finally:
            os.unlink(key_path)


class TestKeyRotation:
    """Test key rotation functionality."""
    
    def test_rotate_session_key(self):
        """Test session key rotation."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            policy = KeyRotationPolicy(
                rotation_interval_hours=24,
                grace_period_minutes=5
            )
            key_manager = KeyManager(master_key_source=key_path, rotation_policy=policy)
            
            # Derive initial key
            old_key = key_manager.derive_session_key('session1', 'key1')
            
            # Rotate key
            new_key = key_manager.rotate_session_key('session1')
            
            # Keys should be different
            assert new_key != old_key
            
            # Both should be valid during grace period
            assert key_manager.is_key_in_grace_period('session1', old_key)
            assert key_manager.is_key_in_grace_period('session1', new_key)
        finally:
            os.unlink(key_path)
    
    def test_rotate_nonexistent_session(self):
        """Test that rotating nonexistent session raises error."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            with pytest.raises(KeyError, match="not found"):
                key_manager.rotate_session_key('nonexistent')
        finally:
            os.unlink(key_path)
    
    def test_grace_period_expiration(self):
        """Test that old keys expire after grace period."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            # Very short grace period for testing
            policy = KeyRotationPolicy(
                rotation_interval_hours=1,
                grace_period_minutes=0  # No grace period
            )
            key_manager = KeyManager(master_key_source=key_path, rotation_policy=policy)
            
            # Derive and rotate
            old_key = key_manager.derive_session_key('session1', 'key1')
            new_key = key_manager.rotate_session_key('session1')
            
            # Manually expire the grace period
            key_manager.session_keys['session1'].previous_key_expires_at = time.time() - 1
            
            # Old key should no longer be valid
            assert not key_manager.is_key_in_grace_period('session1', old_key)
            # New key should still be valid
            assert key_manager.is_key_in_grace_period('session1', new_key)
        finally:
            os.unlink(key_path)


class TestSecureKeyDeletion:
    """Test secure key deletion."""
    
    def test_secure_delete_key(self):
        """Test that secure_delete_key overwrites memory."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            # Create a key to delete
            test_key = os.urandom(32)
            
            # This should not raise an error
            key_manager.secure_delete_key(test_key)
        finally:
            os.unlink(key_path)
    
    def test_cleanup_expired_keys(self):
        """Test cleanup of expired session keys."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            # Create session with expired key
            key_manager.derive_session_key('session1', 'key1')
            key_manager.session_keys['session1'].expires_at = time.time() - 1
            
            # Cleanup should remove expired session
            key_manager.cleanup_expired_keys()
            
            assert 'session1' not in key_manager.session_keys
        finally:
            os.unlink(key_path)
    
    def test_shutdown_clears_all_keys(self):
        """Test that shutdown securely deletes all keys."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            # Create some session keys
            key_manager.derive_session_key('session1', 'key1')
            key_manager.derive_session_key('session2', 'key2')
            
            # Shutdown
            key_manager.shutdown()
            
            # Session keys should be cleared
            assert len(key_manager.session_keys) == 0
        finally:
            os.unlink(key_path)


class TestSROS2Export:
    """Test SROS2 keystore export."""
    
    def test_export_to_sros2_keystore(self):
        """Test exporting robot keys to SROS2 format."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            # Generate robot key pair
            pub, priv = key_manager.generate_robot_keypair('robot1')
            
            with tempfile.TemporaryDirectory() as tmpdir:
                # Export to SROS2 keystore
                key_manager.export_to_sros2_keystore('robot1', tmpdir)
                
                # Check directory structure
                robot_dir = Path(tmpdir) / 'robot1'
                assert robot_dir.exists()
                
                # Check key file exists with correct permissions (Unix only)
                key_file = robot_dir / 'key.pem'
                assert key_file.exists()
                
                import platform
                if platform.system() != 'Windows':
                    stat_info = key_file.stat()
                    file_mode = stat_info.st_mode & 0o777
                    assert file_mode == 0o600
                
                # Check cert file exists
                cert_file = robot_dir / 'cert.pem'
                assert cert_file.exists()
                
                # Verify content
                with open(key_file, 'rb') as f:
                    exported_priv = f.read()
                assert exported_priv == priv
                
                with open(cert_file, 'rb') as f:
                    exported_pub = f.read()
                assert exported_pub == pub
        finally:
            os.unlink(key_path)
    
    def test_export_nonexistent_robot(self):
        """Test that exporting nonexistent robot raises error."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(os.urandom(32))
            key_path = f.name
        
        try:
            os.chmod(key_path, 0o600)
            key_manager = KeyManager(master_key_source=key_path)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                with pytest.raises(KeyError, match="not found"):
                    key_manager.export_to_sros2_keystore('nonexistent', tmpdir)
        finally:
            os.unlink(key_path)


class TestRotationPolicy:
    """Test key rotation policy validation."""
    
    def test_valid_rotation_policy(self):
        """Test creating valid rotation policy."""
        policy = KeyRotationPolicy(
            rotation_interval_hours=24,
            grace_period_minutes=5,
            auto_rotate_master_key=False
        )
        assert policy.rotation_interval_hours == 24
        assert policy.grace_period_minutes == 5
    
    def test_rotation_interval_too_short(self):
        """Test that rotation interval < 1 hour is rejected."""
        with pytest.raises(ValueError, match="between 1 and 720"):
            KeyRotationPolicy(rotation_interval_hours=0)
    
    def test_rotation_interval_too_long(self):
        """Test that rotation interval > 30 days is rejected."""
        with pytest.raises(ValueError, match="between 1 and 720"):
            KeyRotationPolicy(rotation_interval_hours=721)
    
    def test_negative_grace_period(self):
        """Test that negative grace period is rejected."""
        with pytest.raises(ValueError, match="non-negative"):
            KeyRotationPolicy(
                rotation_interval_hours=24,
                grace_period_minutes=-1
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
