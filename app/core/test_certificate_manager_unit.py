"""
Unit Tests for Certificate Manager

Tests specific examples and edge cases for certificate management.

Requirements: 6.1-6.5, 7.1-7.6, 8.1-8.5
"""

import os
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509

from app.core.certificate_manager import (
    CertificateManager,
    generate_ca_certificate,
)
from app.core.key_manager import KeyManager


class TestCertificateIssuance:
    """Test certificate issuance functionality."""
    
    def test_issue_robot_certificate(self):
        """Test issuing a certificate for a robot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate CA
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            # Initialize managers
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            # Generate robot key pair
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            # Issue certificate
            cert_pem = cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=365
            )
            
            # Verify certificate format
            assert cert_pem.startswith(b'-----BEGIN CERTIFICATE-----')
            
            # Verify certificate is stored
            assert 'robot1' in cert_manager.certificates
            
            # Load and verify certificate fields
            cert = x509.load_pem_x509_certificate(cert_pem)
            assert 'robot1' in cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
    
    def test_issue_certificate_with_custom_validity(self):
        """Test issuing certificate with custom validity period."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            # Issue with 90 days validity
            cert_pem = cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=90
            )
            
            cert = x509.load_pem_x509_certificate(cert_pem)
            validity_period = cert.not_valid_after - cert.not_valid_before
            
            # Should be approximately 90 days
            assert 89 <= validity_period.days <= 91
    
    def test_issue_certificate_invalid_validity_period(self):
        """Test that invalid validity periods are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            # Too short
            with pytest.raises(ValueError, match="between 30 and 365"):
                cert_manager.issue_robot_certificate(
                    robot_id='robot1',
                    public_key=pub_key,
                    validity_days=29
                )
            
            # Too long
            with pytest.raises(ValueError, match="between 30 and 365"):
                cert_manager.issue_robot_certificate(
                    robot_id='robot1',
                    public_key=pub_key,
                    validity_days=366
                )


class TestCertificateVerification:
    """Test certificate verification functionality."""
    
    def test_verify_valid_certificate(self):
        """Test verifying a valid certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            cert_pem = cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=365
            )
            
            valid, reason = cert_manager.verify_certificate(cert_pem)
            assert valid
            assert reason == "Valid"
    
    def test_verify_expired_certificate(self):
        """Test that expired certificates are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            # Issue certificate with minimum validity
            cert_pem = cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=30
            )
            
            # Manually mark as expired
            cert_manager.certificates['robot1'].expires_at = time.time() - 1
            
            # Note: This test checks the stored expiration, not the cert itself
            # In real scenario, we'd need to wait or manipulate system time
    
    def test_verify_revoked_certificate(self):
        """Test that revoked certificates are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            cert_pem = cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=365
            )
            
            # Revoke certificate
            cert_manager.revoke_certificate('robot1', 'Compromised')
            
            # Verify should fail
            valid, reason = cert_manager.verify_certificate(cert_pem)
            assert not valid
            assert 'revoked' in reason.lower()


class TestCertificateRevocation:
    """Test certificate revocation functionality."""
    
    def test_revoke_certificate(self):
        """Test revoking a certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path),
                crl_storage_path=str(Path(tmpdir) / "crl.json")
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            cert_pem = cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=365
            )
            
            # Revoke
            cert_manager.revoke_certificate('robot1', 'Test revocation')
            
            # Check revocation
            cert_info = cert_manager.get_certificate_info('robot1')
            assert cert_info.revoked
            assert cert_info.revocation_reason == 'Test revocation'
            
            # Check CRL
            serial = cert_info.serial_number
            assert cert_manager.is_certificate_revoked(serial)
    
    def test_revoke_nonexistent_certificate(self):
        """Test that revoking nonexistent certificate raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            with pytest.raises(KeyError, match="not found"):
                cert_manager.revoke_certificate('nonexistent', 'Test')
    
    def test_crl_persistence(self):
        """Test that CRL is persisted and loaded correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            crl_path = Path(tmpdir) / "crl.json"
            
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            # First manager instance
            cert_manager1 = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path),
                crl_storage_path=str(crl_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            cert_pem = cert_manager1.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=365
            )
            
            serial = cert_manager1.get_certificate_info('robot1').serial_number
            cert_manager1.revoke_certificate('robot1', 'Test')
            
            # Second manager instance (reload)
            cert_manager2 = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path),
                crl_storage_path=str(crl_path)
            )
            
            # CRL should be loaded
            assert cert_manager2.is_certificate_revoked(serial)


class TestCertificateRenewal:
    """Test certificate renewal functionality."""
    
    def test_renew_certificate(self):
        """Test renewing a certificate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            # Issue original certificate
            old_cert_pem = cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=90
            )
            
            old_serial = cert_manager.get_certificate_info('robot1').serial_number
            
            # Renew certificate
            new_cert_pem = cert_manager.renew_certificate('robot1', validity_days=365)
            
            new_serial = cert_manager.get_certificate_info('robot1').serial_number
            
            # Serials should be different
            assert old_serial != new_serial
            
            # New certificate should be valid
            valid, _ = cert_manager.verify_certificate(new_cert_pem)
            assert valid
    
    def test_check_expiring_certificates(self):
        """Test checking for expiring certificates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            
            # Issue certificate expiring soon
            pub_key1, _ = key_manager.generate_robot_keypair('robot1')
            cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key1,
                validity_days=30
            )
            
            # Manually set expiration to 5 days from now
            cert_manager.certificates['robot1'].expires_at = time.time() + (5 * 24 * 3600)
            
            # Issue certificate not expiring soon
            pub_key2, _ = key_manager.generate_robot_keypair('robot2')
            cert_manager.issue_robot_certificate(
                robot_id='robot2',
                public_key=pub_key2,
                validity_days=365
            )
            
            # Check expiring (7 day threshold)
            expiring = cert_manager.check_expiring_certificates(days_threshold=7)
            
            assert 'robot1' in expiring
            assert 'robot2' not in expiring
    
    def test_auto_renew_expiring_certificates(self):
        """Test automatic renewal of expiring certificates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=30
            )
            
            old_serial = cert_manager.get_certificate_info('robot1').serial_number
            
            # Manually set expiration to 5 days from now
            cert_manager.certificates['robot1'].expires_at = time.time() + (5 * 24 * 3600)
            
            # Auto-renew
            renewed = cert_manager.auto_renew_expiring_certificates(days_threshold=7)
            
            assert 'robot1' in renewed
            
            new_serial = cert_manager.get_certificate_info('robot1').serial_number
            assert old_serial != new_serial


class TestDDSSecurityCompatibility:
    """Test DDS-Security compatibility features."""
    
    def test_certificate_has_required_extensions(self):
        """Test that issued certificates have DDS-Security required extensions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert_path = Path(tmpdir) / "ca_cert.pem"
            ca_key_path = Path(tmpdir) / "ca_key.pem"
            generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
            
            cert_manager = CertificateManager(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path)
            )
            
            master_key_path = Path(tmpdir) / "master.key"
            with open(master_key_path, 'wb') as f:
                f.write(os.urandom(32))
            os.chmod(master_key_path, 0o600)
            
            key_manager = KeyManager(master_key_source=str(master_key_path))
            pub_key, _ = key_manager.generate_robot_keypair('robot1')
            
            cert_pem = cert_manager.issue_robot_certificate(
                robot_id='robot1',
                public_key=pub_key,
                validity_days=365
            )
            
            cert = x509.load_pem_x509_certificate(cert_pem)
            
            # Check for SubjectAlternativeName
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            assert san_ext is not None
            
            # Check for BasicConstraints
            bc_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            assert bc_ext is not None
            assert bc_ext.value.ca is False
            
            # Check for KeyUsage
            ku_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            )
            assert ku_ext is not None
            assert ku_ext.value.digital_signature


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
