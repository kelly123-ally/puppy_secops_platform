"""
Property-Based Tests for Audit Logger

Tests universal correctness properties using hypothesis framework.

Requirements: 9.2, 24.2, 24.3, 24.4
"""

import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from app.core.audit_logger import AuditLogger


# ============================================================================
# Property 9: Audit Chain Hash Linking
# ============================================================================

@given(
    events=st.lists(
        st.tuples(
            st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',))),  # category
            st.text(min_size=1, max_size=100, alphabet=st.characters(blacklist_categories=('Cs',))),  # title
            st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',)))   # actor
        ),
        min_size=2,
        max_size=20
    )
)
@settings(max_examples=50, deadline=None)
def test_property_9_audit_chain_hash_linking(events):
    """
    **Property 9: Audit Chain Hash Linking**
    
    **Validates: Requirement 9.2**
    
    For any sequence of audit events, each event's previous_hash field SHALL 
    equal the event_hash of the preceding event, forming an unbroken 
    cryptographic chain from genesis to current.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize audit logger
        logger = AuditLogger(
            signing_key_path=str(Path(tmpdir) / "signing_key.pem"),
            genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
            storage_path=str(Path(tmpdir) / "events.json")
        )
        
        # Log all events
        for category, title, actor in events:
            logger.log_event(
                category=category,
                title=title,
                actor=actor,
                details={"test": "data"}
            )
        
        # Property: Each event's previous_hash equals prior event's event_hash
        for i in range(1, len(logger.events)):
            current_event = logger.events[i]
            previous_event = logger.events[i - 1]
            
            assert current_event.previous_hash == previous_event.event_hash, \
                f"Event {i} previous_hash does not match event {i-1} event_hash"
        
        # Property: First event has empty previous_hash
        if logger.events:
            assert logger.events[0].previous_hash == "", \
                "First event must have empty previous_hash"
        
        # Property: Genesis hash matches first event hash
        if logger.events:
            assert logger.genesis_hash == logger.events[0].event_hash, \
                "Genesis hash must match first event hash"


# ============================================================================
# Property 8: Audit Chain Integrity Verification
# ============================================================================

@given(
    events=st.lists(
        st.tuples(
            st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',))),
            st.text(min_size=1, max_size=100, alphabet=st.characters(blacklist_categories=('Cs',))),
            st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',)))
        ),
        min_size=1,
        max_size=15
    ),
    tamper_index=st.integers(min_value=-1, max_value=14)
)
@settings(max_examples=50, deadline=None)
def test_property_8_audit_chain_integrity_verification(events, tamper_index):
    """
    **Property 8: Audit Chain Integrity Verification**
    
    **Validates: Requirements 24.2, 24.3, 24.4**
    
    For any audit chain, if no events have been tampered with, integrity 
    verification SHALL succeed and report the total number of validated events; 
    if any event has been tampered with, verification SHALL fail and return 
    the index of the first tampered event.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize audit logger
        logger = AuditLogger(
            signing_key_path=str(Path(tmpdir) / "signing_key.pem"),
            genesis_hash_path=str(Path(tmpdir) / "genesis.txt"),
            storage_path=str(Path(tmpdir) / "events.json")
        )
        
        # Log all events
        for category, title, actor in events:
            logger.log_event(
                category=category,
                title=title,
                actor=actor,
                details={"test": "data"}
            )
        
        # Determine if we should tamper
        should_tamper = 0 <= tamper_index < len(logger.events)
        
        if not should_tamper:
            # Property: Untampered chain passes verification
            valid, first_tampered = logger.verify_chain_integrity()
            assert valid, "Untampered chain must pass verification"
            assert first_tampered is None, \
                "Untampered chain must return None for tampered index"
        else:
            # Tamper with an event
            logger.events[tamper_index].title = "TAMPERED"
            
            # Property: Tampered chain fails verification
            valid, first_tampered = logger.verify_chain_integrity()
            assert not valid, "Tampered chain must fail verification"
            
            # Property: Returns correct tampered index
            assert first_tampered is not None, \
                "Tampered chain must return tampered index"
            assert first_tampered == tamper_index, \
                f"Expected tampered index {tamper_index}, got {first_tampered}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
