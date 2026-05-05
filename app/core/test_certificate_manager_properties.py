"""
Property-Based Tests for Certificate Manager

Tests universal correctness properties using hypothesis framework.

Requirements: 7.2, 7.5
"""

import os
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from app.core.certificate_manager import CertificateManager, generate_ca_certificate
from app.core.key_manager import KeyManager


# ============================================================================
# Property 10: Certificate Revocation Enforcement
# ============================================================================

@given(
    robot_id=st.text(min_size=1, max_size=32, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd'),
        min_codepoint=ord('a'),
        max_codepoint=ord('z')
    ) | st.just('_')),
    revocation_reason=st.text(min_size=1, max_size=100, alphabet=st.characters(
        blacklist_categories=('Cs',)
    ))
)
@settings(max_examples=50, deadline=None)
def test_property_10_certificate_revocation_enforcement(robot_id, revocation_reason):
    """
    **Property 10: Certificate Revocation Enforcement**
    
    **Validates: Requirements 7.2, 7.5**
    
    For any robot certificate that has been revoked, all subsequent 
    authentication attempts using that certificate SHALL be rejected, and 
    the certificate SHALL appear in the revocation list.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Generate CA certificate
        ca_cert_path = Path(tmpdir) / "ca_cert.pem"
        ca_key_path = Path(tmpdir) / "ca_key.pem"
        generate_ca_certificate(str(ca_cert_path), str(ca_key_path))
        
        # Initialize certificate manager
        cert_manager = CertificateManager(
            ca_cert_path=str(ca_cert_path),
            ca_key_path=str(ca_key_path),
            crl_storage_path=str(Path(tmpdir) / "crl.json")
        )
        
        # Generate robot key pair
        master_key_path = Path(tmpdir) / "master.key"
        with open(master_key_path, 'wb') as f:
            f.write(os.urandom(32))
        os.chmod(master_key_path, 0o600)
        
        key_manager = KeyManager(master_key_source=str(master_key_path))
        pub_key, priv_key = key_manager.generate_robot_keypair(robot_id)
        
        # Issue certificate
        cert_pem = cert_manager.issue_robot_certificate(
            robot_id=robot_id,
            public_key=pub_key,
            validity_days=365
        )
        
        # Property: Certificate should be valid before revocation
        valid, reason = cert_manager.verify_certificate(cert_pem)
        assert valid, f"Certificate should be valid before revocation, but got: {reason}"
        
        # Get serial number for CRL check
        cert_info = cert_manager.get_certificate_info(robot_id)
        serial_number = cert_info.serial_number
        
        # Property: Certificate should not be in CRL before revocation
        assert not cert_manager.is_certificate_revoked(serial_number), \
            "Certificate should not be in CRL before revocation"
        
        # Revoke certificate
        cert_manager.revoke_certificate(robot_id, revocation_reason)
        
        # Property: Certificate must be rejected after revocation
        valid, reason = cert_manager.verify_certificate(cert_pem)
        assert not valid, "Revoked certificate must be rejected"
        assert "revoked" in reason.lower(), \
            f"Rejection reason should mention revocation, got: {reason}"
        
        # Property: Certificate must appear in revocation list
        assert cert_manager.is_certificate_revoked(serial_number), \
            "Revoked certificate must appear in CRL"
        
        # Property: Certificate must be in CRL list
        crl_list = cert_manager.get_revocation_list()
        assert serial_number in crl_list, \
            f"Serial number {serial_number} must be in CRL list"
        
        # Property: Certificate info must be marked as revoked
        cert_info = cert_manager.get_certificate_info(robot_id)
        assert cert_info.revoked is True, \
            "Certificate info must have revoked flag set"
        assert cert_info.revocation_reason == revocation_reason, \
            "Certificate info must contain revocation reason"
        
        # Property: Revocation is persistent (verify again)
        valid, reason = cert_manager.verify_certificate(cert_pem)
        assert not valid, "Revoked certificate must remain rejected"
        
        # Property: CRL persistence - reload and verify
        cert_manager2 = CertificateManager(
            ca_cert_path=str(ca_cert_path),
            ca_key_path=str(ca_key_path),
            crl_storage_path=str(Path(tmpdir) / "crl.json")
        )
        
        assert cert_manager2.is_certificate_revoked(serial_number), \
            "Revoked certificate must be in CRL after reload"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
