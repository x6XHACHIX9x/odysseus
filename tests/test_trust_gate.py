import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from odysseus.trust.gate import RegistrySnapshot, ReleaseGateVerifier, SubjectSpec
from odysseus.trust.validator import TrustRegistryValidator
from tests.test_trust_validator import build_signed_entry, key_ring  # noqa: F401


@pytest.fixture()
def validator(key_ring):  # noqa: F811
    trusted, _ = key_ring
    schema_path = Path("schemas/ops-v3-203/trust-registry-entry.v1.json")
    return TrustRegistryValidator(schema_path=schema_path, trusted_keys=trusted)


def default_subject(cert_id: str) -> SubjectSpec:
    return SubjectSpec(
        certification_id=cert_id,
        artifact_sha256="a" * 64,
        sbom_sha256="b" * 64,
        environment_baseline_sha256="c" * 64,
        ops_v3_202_challenge_nonce="nonce-" + ("d" * 32),
    )


def test_gate_allows_active_certified_chain(validator, key_ring):  # noqa: F811
    cert_id = str(uuid.uuid4())
    now = datetime(2026, 11, 13, 20, 0, 0, tzinfo=timezone.utc)

    e1 = build_signed_entry(
        key_ring,
        seq=1,
        prev_sha256="0" * 64,
        cert_id=cert_id,
        from_state="PENDING",
        to_state="CERTIFIED",
        trigger_class="VALIDATION_PASS",
        signer_key_ids=["key-policy-01"],
    )

    gate = ReleaseGateVerifier(
        validator=validator,
        fetch_snapshot=lambda _: RegistrySnapshot(
            fetched_at_utc=now - timedelta(seconds=10),
            registry_clock_utc=now,
            entries=[e1],
        ),
        clock=lambda: now,
    )

    decision = gate.evaluate_release(default_subject(cert_id))
    assert decision.allowed is True
    assert decision.decision == "ALLOW"
    assert decision.effective_state == "CERTIFIED"
    assert decision.latest_sequence_number == 1
    assert decision.rollback_running_workloads is False


def test_gate_denies_suspended_or_revoked_chain_without_rollback(validator, key_ring):  # noqa: F811
    cert_id = str(uuid.uuid4())
    now = datetime(2026, 11, 13, 20, 0, 0, tzinfo=timezone.utc)

    e1 = build_signed_entry(
        key_ring,
        seq=1,
        prev_sha256="0" * 64,
        cert_id=cert_id,
        from_state="PENDING",
        to_state="CERTIFIED",
        trigger_class="VALIDATION_PASS",
        signer_key_ids=["key-policy-01"],
    )
    e1_hash = hashlib.sha256(e1["canonical_payload_b64"].encode("ascii")).hexdigest()
    e2 = build_signed_entry(
        key_ring,
        seq=2,
        prev_sha256=e1_hash,
        cert_id=cert_id,
        from_state="CERTIFIED",
        to_state="SUSPENDED",
        trigger_class="KEY_COMPROMISE",
        signer_key_ids=["key-policy-01"],
    )

    gate = ReleaseGateVerifier(
        validator=validator,
        fetch_snapshot=lambda _: RegistrySnapshot(
            fetched_at_utc=now,
            registry_clock_utc=now,
            entries=[e1, e2],
        ),
        clock=lambda: now,
    )

    decision = gate.evaluate_release(default_subject(cert_id))
    assert decision.allowed is False
    assert decision.decision == "DENY"
    assert decision.effective_state == "SUSPENDED"
    assert decision.latest_sequence_number == 2
    assert decision.rollback_running_workloads is False


def test_gate_fails_closed_when_registry_unavailable(validator):
    cert_id = str(uuid.uuid4())
    now = datetime(2026, 11, 13, 20, 0, 0, tzinfo=timezone.utc)

    def broken_registry(_: str) -> RegistrySnapshot:
        raise ConnectionError("Trust registry endpoint timed out")

    gate = ReleaseGateVerifier(
        validator=validator,
        fetch_snapshot=broken_registry,
        clock=lambda: now,
    )

    decision = gate.evaluate_release(default_subject(cert_id))
    assert decision.allowed is False
    assert decision.decision == "DENY"
    assert "unavailable (fail-closed)" in decision.reason
    assert decision.rollback_running_workloads is False


def test_gate_denies_expired_snapshot_ttl(validator, key_ring):  # noqa: F811
    cert_id = str(uuid.uuid4())
    now = datetime(2026, 11, 13, 20, 0, 0, tzinfo=timezone.utc)

    e1 = build_signed_entry(
        key_ring,
        seq=1,
        prev_sha256="0" * 64,
        cert_id=cert_id,
        from_state="PENDING",
        to_state="CERTIFIED",
        trigger_class="VALIDATION_PASS",
        signer_key_ids=["key-policy-01"],
    )

    gate = ReleaseGateVerifier(
        validator=validator,
        fetch_snapshot=lambda _: RegistrySnapshot(
            fetched_at_utc=now - timedelta(seconds=61),  # Exceeds 60s max TTL
            registry_clock_utc=now,
            entries=[e1],
        ),
        max_cache_ttl_seconds=60.0,
        clock=lambda: now,
    )

    decision = gate.evaluate_release(default_subject(cert_id))
    assert decision.allowed is False
    assert decision.decision == "DENY"
    assert "snapshot expired" in decision.reason


def test_gate_denies_excessive_clock_skew(validator, key_ring):  # noqa: F811
    cert_id = str(uuid.uuid4())
    now = datetime(2026, 11, 13, 20, 0, 0, tzinfo=timezone.utc)

    e1 = build_signed_entry(
        key_ring,
        seq=1,
        prev_sha256="0" * 64,
        cert_id=cert_id,
        from_state="PENDING",
        to_state="CERTIFIED",
        trigger_class="VALIDATION_PASS",
        signer_key_ids=["key-policy-01"],
    )

    gate = ReleaseGateVerifier(
        validator=validator,
        fetch_snapshot=lambda _: RegistrySnapshot(
            fetched_at_utc=now,
            registry_clock_utc=now + timedelta(seconds=8),  # Exceeds 5s skew limit
            entries=[e1],
        ),
        clock=lambda: now,
    )

    decision = gate.evaluate_release(default_subject(cert_id))
    assert decision.allowed is False
    assert decision.decision == "DENY"
    assert "clock skew" in decision.reason


def test_gate_denies_subject_binding_mismatch(validator, key_ring):  # noqa: F811
    cert_id = str(uuid.uuid4())
    now = datetime(2026, 11, 13, 20, 0, 0, tzinfo=timezone.utc)

    e1 = build_signed_entry(
        key_ring,
        seq=1,
        prev_sha256="0" * 64,
        cert_id=cert_id,
        from_state="PENDING",
        to_state="CERTIFIED",
        trigger_class="VALIDATION_PASS",
        signer_key_ids=["key-policy-01"],
    )

    gate = ReleaseGateVerifier(
        validator=validator,
        fetch_snapshot=lambda _: RegistrySnapshot(
            fetched_at_utc=now,
            registry_clock_utc=now,
            entries=[e1],
        ),
        clock=lambda: now,
    )

    wrong_artifact = SubjectSpec(
        certification_id=cert_id,
        artifact_sha256="9" * 64,  # Does not match "a" * 64 in certified entry
        sbom_sha256="b" * 64,
        environment_baseline_sha256="c" * 64,
        ops_v3_202_challenge_nonce="nonce-" + ("d" * 32),
    )

    decision = gate.evaluate_release(wrong_artifact)
    assert decision.allowed is False
    assert decision.decision == "DENY"
    assert "Subject binding mismatch" in decision.reason