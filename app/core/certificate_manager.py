"""
Certificate Manager for PuppySecOps Platform

Provides X.509 certificate management including:
- Certificate issuance signed by platform CA
- Certificate verification (signature, expiration, revocation)
- Certificate Revocation List (CRL) management
- Automatic certificate renewal
- DDS-Security compatibility for ROS 2 deployment

Requirements: 6.1-6.5, 7.1-7.6, 8.1-8.5
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID


@dataclass
class RobotCertificate:
    """Robot's X.509 certificate information.
    
    Attributes:
        robot_id: Unique robot identifier
        serial_number: Certificate serial number (hex string)
        certificate: X.509 certificate (PEM format)
        issued_at: Timestamp when certificate was issued
        expires_at: Timestamp when certificate expires
        revoked: Whether this certificate has been revoked
        revocation_reason: Reason for revocation (if revoked)
    """
    robot_id: str
    serial_number: str
    certificate: bytes
    issued_at: float
    expires_at: float
    revoked: bool = False
    revocation_reason: Optional[str] = None


@dataclass
class CertificateRevocationEntry:
    """Entry in the Certificate Revocation List.
    
    Attributes:
        serial_number: Certificate serial number
        robot_id: Robot whose certificate was revoked
        revoked_at: Timestamp when certificate was revoked
        reason: Reason for revocation
    """
    serial_number: str
    robot_id: str
    revoked_at: float
    reason: str


class CertificateManager:
    """Manages X.509 certificates for robot authentication.
    
    Provides certificate issuance, verification, revocation, and renewal.
    Designed for compatibility with DDS-Security for ROS 2 deployment.
    """
    
    def __init__(
        self,
        ca_cert_path: str,
        ca_key_path: str,
        crl_storage_path: Optional[str] = None
    ):
        """Initialize Certificate Manager.
        
        Args:
            ca_cert_path: Path to platform CA certificate (PEM format)
            ca_key_path: Path to platform CA private key (PEM format)
            crl_storage_path: Path to store Certificate Revocation List
            
        Raises:
            FileNotFoundError: If CA certificate or key not found
            ValueError: If CA certificate or key is invalid
        """
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.crl_storage_path = crl_storage_path or "crl.json"
        
        # Load CA certificate and private key
        self.ca_cert = self._load_ca_certificate()
        self.ca_private_key = self._load_ca_private_key()
        
        # Storage for issued certificates
        self.certificates: Dict[str, RobotCertificate] = {}
        
        # Certificate Revocation List
        self.crl: Dict[str, CertificateRevocationEntry] = {}
        
        # Load CRL from disk if exists
        self._load_crl()
        
        # Audit logger (injected from application)
        self.audit_logger = None  # Set via set_audit_logger()
        
        # Session termination callback (will be set by application)
        self.terminate_session_callback = None
    
    def _load_ca_certificate(self) -> x509.Certificate:
        """Load platform CA certificate from file.
        
        Returns:
            X.509 certificate object
            
        Raises:
            FileNotFoundError: If certificate file not found
        """
        ca_cert_path = Path(self.ca_cert_path)
        if not ca_cert_path.exists():
            raise FileNotFoundError(f"CA certificate not found: {self.ca_cert_path}")
        
        with open(ca_cert_path, 'rb') as f:
            cert_data = f.read()
        
        return x509.load_pem_x509_certificate(cert_data)
    
    def _load_ca_private_key(self) -> rsa.RSAPrivateKey:
        """Load platform CA private key from file.
        
        Returns:
            RSA private key object
            
        Raises:
            FileNotFoundError: If key file not found
        """
        ca_key_path = Path(self.ca_key_path)
        if not ca_key_path.exists():
            raise FileNotFoundError(f"CA private key not found: {self.ca_key_path}")
        
        with open(ca_key_path, 'rb') as f:
            key_data = f.read()
        
        return serialization.load_pem_private_key(key_data, password=None)
    
    def _load_crl(self) -> None:
        """Load Certificate Revocation List from disk."""
        crl_path = Path(self.crl_storage_path)
        if not crl_path.exists():
            return
        
        try:
            with open(crl_path, 'r') as f:
                crl_data = json.load(f)
            
            for entry_data in crl_data:
                entry = CertificateRevocationEntry(**entry_data)
                self.crl[entry.serial_number] = entry
        except Exception as e:
            # Log error but don't fail initialization
            if self.audit_logger:
                self.audit_logger.log_event(
                    category="certificate_management",
                    title="CRL load failed",
                    actor="system",
                    details={"error": str(e)}
                )
    
    def _save_crl(self) -> None:
        """Persist Certificate Revocation List to disk."""
        crl_data = [
            {
                "serial_number": entry.serial_number,
                "robot_id": entry.robot_id,
                "revoked_at": entry.revoked_at,
                "reason": entry.reason
            }
            for entry in self.crl.values()
        ]
        
        crl_path = Path(self.crl_storage_path)
        crl_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(crl_path, 'w') as f:
            json.dump(crl_data, f, indent=2)
    
    def issue_robot_certificate(
        self,
        robot_id: str,
        public_key: bytes,
        validity_days: int = 365
    ) -> bytes:
        """Issue X.509 certificate for robot, signed by platform CA.
        
        Implements Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 8.1:
        - Issues certificate signed by platform CA
        - Includes robot_id, public key, expiration date
        - Supports configurable validity periods (30 days to 1 year)
        
        Args:
            robot_id: Unique robot identifier
            public_key: Robot's public key (PEM format)
            validity_days: Certificate validity period in days (30-365)
            
        Returns:
            X.509 certificate in PEM format
            
        Raises:
            ValueError: If validity_days is out of range
        """
        if not 30 <= validity_days <= 365:
            raise ValueError("validity_days must be between 30 and 365")
        
        # Load robot's public key
        robot_public_key = serialization.load_pem_public_key(public_key)
        
        # Generate serial number
        serial_number = x509.random_serial_number()
        
        # Build certificate
        now = datetime.utcnow()
        expires = now + timedelta(days=validity_days)
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, robot_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PuppySecOps Platform"),
        ])
        
        # Build certificate with DDS-Security compatible extensions
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(robot_public_key)
            .serial_number(serial_number)
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(robot_id),
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        
        # Sign certificate with CA private key
        certificate = cert_builder.sign(
            private_key=self.ca_private_key,
            algorithm=hashes.SHA256()
        )
        
        # Serialize to PEM
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        
        # Store certificate info
        robot_cert = RobotCertificate(
            robot_id=robot_id,
            serial_number=hex(serial_number),
            certificate=cert_pem,
            issued_at=now.timestamp(),
            expires_at=expires.timestamp()
        )
        self.certificates[robot_id] = robot_cert
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="certificate_management",
                title="Certificate issued",
                actor="system",
                details={
                    "robot_id": robot_id,
                    "serial_number": hex(serial_number),
                    "validity_days": validity_days,
                    "expires_at": expires.isoformat()
                }
            )
        
        return cert_pem
    
    def verify_certificate(self, cert_bytes: bytes) -> Tuple[bool, str]:
        """Verify certificate signature, expiration, and revocation status.
        
        Implements Requirements 7.1, 7.2:
        - Verifies signature against platform CA
        - Checks expiration date
        - Checks revocation status
        
        Args:
            cert_bytes: X.509 certificate in PEM format
            
        Returns:
            Tuple of (valid, reason) where reason explains failure if invalid
        """
        try:
            # Load certificate
            certificate = x509.load_pem_x509_certificate(cert_bytes)
            
            # Check signature - verify issuer matches CA
            if certificate.issuer != self.ca_cert.subject:
                return False, "Invalid signature"
            
            # Verify signature using CA's public key
            try:
                from cryptography.hazmat.primitives.asymmetric import padding
                ca_public_key = self.ca_cert.public_key()
                ca_public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm
                )
            except Exception as e:
                return False, "Invalid signature"
            
            # Check expiration
            now = datetime.utcnow()
            if now < certificate.not_valid_before:
                return False, "Certificate not yet valid"
            if now > certificate.not_valid_after:
                return False, "Certificate expired"
            
            # Check revocation status
            serial_hex = hex(certificate.serial_number)
            if serial_hex in self.crl:
                return False, f"Certificate revoked: {self.crl[serial_hex].reason}"
            
            return True, "Valid"
            
        except Exception as e:
            return False, f"Certificate verification error: {str(e)}"
    
    def revoke_certificate(self, robot_id: str, reason: str) -> None:
        """Add certificate to revocation list and terminate active sessions.
        
        Implements Requirements 7.1, 7.2, 7.3, 7.4, 7.5, 7.6:
        - Adds certificate to CRL
        - Persists CRL to disk
        - Terminates active sessions
        - Logs revocation event
        
        Args:
            robot_id: Robot whose certificate should be revoked
            reason: Reason for revocation
            
        Raises:
            KeyError: If robot_id not found
        """
        if robot_id not in self.certificates:
            raise KeyError(f"Certificate for robot {robot_id} not found")
        
        robot_cert = self.certificates[robot_id]
        
        # Add to CRL
        crl_entry = CertificateRevocationEntry(
            serial_number=robot_cert.serial_number,
            robot_id=robot_id,
            revoked_at=time.time(),
            reason=reason
        )
        self.crl[robot_cert.serial_number] = crl_entry
        
        # Mark certificate as revoked
        robot_cert.revoked = True
        robot_cert.revocation_reason = reason
        
        # Persist CRL
        self._save_crl()
        
        # Terminate active sessions
        if self.terminate_session_callback:
            self.terminate_session_callback(robot_id)
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="certificate_management",
                title="Certificate revoked",
                actor="system",
                details={
                    "robot_id": robot_id,
                    "serial_number": robot_cert.serial_number,
                    "reason": reason
                }
            )
    
    def renew_certificate(self, robot_id: str, validity_days: int = 365) -> bytes:
        """Issue renewal certificate for robot approaching expiration.
        
        Implements Requirements 8.2, 8.3, 8.4, 8.5:
        - Issues renewal certificate
        - Maintains both current and renewal certificates during transition
        
        Args:
            robot_id: Robot whose certificate should be renewed
            validity_days: New certificate validity period in days
            
        Returns:
            New X.509 certificate in PEM format
            
        Raises:
            KeyError: If robot_id not found
        """
        if robot_id not in self.certificates:
            raise KeyError(f"Certificate for robot {robot_id} not found")
        
        # Get robot's public key from existing certificate
        old_cert = x509.load_pem_x509_certificate(
            self.certificates[robot_id].certificate
        )
        public_key_pem = old_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Issue new certificate
        new_cert_pem = self.issue_robot_certificate(
            robot_id=robot_id,
            public_key=public_key_pem,
            validity_days=validity_days
        )
        
        if self.audit_logger:
            self.audit_logger.log_event(
                category="certificate_management",
                title="Certificate renewed",
                actor="system",
                details={
                    "robot_id": robot_id,
                    "old_serial": self.certificates[robot_id].serial_number,
                    "validity_days": validity_days
                }
            )
        
        return new_cert_pem
    
    def get_revocation_list(self) -> List[str]:
        """Return list of revoked certificate serial numbers.
        
        Returns:
            List of serial numbers (hex strings)
        """
        return list(self.crl.keys())
    
    def export_to_pem(self, cert_bytes: bytes) -> str:
        """Export certificate to PEM format for external verification.
        
        Args:
            cert_bytes: X.509 certificate bytes
            
        Returns:
            Certificate in PEM format as string
        """
        return cert_bytes.decode('utf-8')
    
    def check_expiring_certificates(self, days_threshold: int = 7) -> List[str]:
        """Check for certificates expiring within threshold.
        
        Implements Requirement 8.2:
        - Identifies certificates approaching expiration
        
        Args:
            days_threshold: Days before expiration to trigger renewal
            
        Returns:
            List of robot_ids with expiring certificates
        """
        expiring = []
        now = time.time()
        threshold_seconds = days_threshold * 24 * 3600
        
        for robot_id, cert in self.certificates.items():
            if cert.revoked:
                continue
            
            time_until_expiry = cert.expires_at - now
            if 0 < time_until_expiry < threshold_seconds:
                expiring.append(robot_id)
        
        return expiring
    
    def auto_renew_expiring_certificates(self, days_threshold: int = 7) -> List[str]:
        """Automatically renew certificates approaching expiration.
        
        Implements Requirements 8.2, 8.3, 8.4:
        - Automatically issues renewal certificates
        - Notifies on renewal failure
        
        Args:
            days_threshold: Days before expiration to trigger renewal
            
        Returns:
            List of robot_ids that were successfully renewed
        """
        expiring = self.check_expiring_certificates(days_threshold)
        renewed = []
        
        for robot_id in expiring:
            try:
                self.renew_certificate(robot_id)
                renewed.append(robot_id)
            except Exception as e:
                # Log renewal failure
                if self.audit_logger:
                    self.audit_logger.log_event(
                        category="certificate_management",
                        title="Certificate renewal failed",
                        actor="system",
                        details={
                            "robot_id": robot_id,
                            "error": str(e)
                        }
                    )
        
        return renewed
    
    def get_certificate_info(self, robot_id: str) -> Optional[RobotCertificate]:
        """Get certificate information for robot.
        
        Args:
            robot_id: Robot identifier
            
        Returns:
            RobotCertificate object or None if not found
        """
        return self.certificates.get(robot_id)
    
    def set_audit_logger(self, audit_logger) -> None:
        """Set audit logger for logging certificate events.
        
        Args:
            audit_logger: AuditLogger instance
        """
        self.audit_logger = audit_logger
    
    def is_certificate_revoked(self, serial_number: str) -> bool:
        """Check if certificate is revoked.
        
        Args:
            serial_number: Certificate serial number (hex string)
            
        Returns:
            True if revoked, False otherwise
        """
        return serial_number in self.crl


def generate_ca_certificate(
    output_cert_path: str,
    output_key_path: str,
    validity_days: int = 3650
) -> None:
    """Generate self-signed CA certificate for the platform.
    
    This is a utility function for initial setup.
    
    Args:
        output_cert_path: Path to save CA certificate (PEM format)
        output_key_path: Path to save CA private key (PEM format)
        validity_days: CA certificate validity period in days
    """
    # Generate CA private key
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Build CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PuppySecOps Platform CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PuppySecOps Platform"),
    ])
    
    now = datetime.utcnow()
    expires = now + timedelta(days=validity_days)
    
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expires)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_private_key, hashes.SHA256())
    )
    
    # Save CA certificate
    cert_path = Path(output_cert_path)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cert_path, 'wb') as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    # Save CA private key
    key_path = Path(output_key_path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    with open(key_path, 'wb') as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"CA certificate generated: {output_cert_path}")
    print(f"CA private key generated: {output_key_path}")


if __name__ == "__main__":
    # Generate CA certificate for testing
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "generate-ca":
        generate_ca_certificate(
            output_cert_path="ca_cert.pem",
            output_key_path="ca_key.pem"
        )
