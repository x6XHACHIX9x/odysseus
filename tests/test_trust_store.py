import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from odysseus.trust.gate import ReleaseGateVerifier, SubjectSpec
from odysseus.trust.store import AppendOnlyTrustStore, TrustRegistryStoreError
from odysseus.trust.validator import TrustRegistryValidator, TrustValidationError
from tests.test_trust_validator import build_signed_entry, key_ring  # noqa: F401


@pytest.fixture()
def validator(key_ring):  # noqa: F811
    trusted, _ = key_ring
    schema_path = Path("schemas/ops-v3-203/trust-registry-entry.v1.json")
    return TrustRegistryValidator(schema_path=schema_path, trusted_keys=trusted)


def test_end_to_end_store_and_release_gate_lifecycle(tmp_path: Path, validator, key_ring):  # noqa: F811
    ledger_file = tmp_path / "trust_registry.jsonl"
    now = datetime(2026, 11, 13, 20, 15, 0, tzinfo=timezone.utc)

    store = AppendOnlyTrustStore(ledger_path=ledger_file, validator=validator, clock=lambda: now)
    gate = ReleaseGateVerifier(
        validator=validator,
        fetch_snapshot=store.get_snapshot,
        clock=lambda: now,
    )

    cert_id = str(uuid.uuid4())
    subject = SubjectSpec(
        certification_id=cert_id,
        artifact_sha256="a" * 64,
        sbom_sha256="b" * 64,
        environment_baseline_sha256="c" * 64,
        ops_v3_202_challenge_nonce="nonce-" + ("d" * 32),
    )

    # 1. Before any entry exists, gate fails closed
    initial_decision = gate.evaluate_release(subject)
    assert initial_decision.allowed is False
    assert initial_decision.decision == "DENY"

    # 2. Append CERTIFIED genesis entry -> Gate ALLOWS
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
    store.append_entry(e1)

    allow_decision = gate.evaluate_release(subject)
    assert allow_decision.allowed is True
    assert allow_decision.decision == "ALLOW"
    assert allow_decision.effective_state == "CERTIFIED"

    # 3. Append SUSPENDED entry -> Gate DENIES immediately without rollback
    e1_hash = hashlib.sha256(e1["canonical_payload_b64"].encode("ascii")).hexdigest()
    e2 = build_signed_entry(
        key_ring,
        seq=2,
        prev_sha256=e1_hash,
        cert_id=cert_id,
        from_state="CERTIFIED",
        to_state="SUSPENDED",
        trigger_class="CRITICAL_VULNERABILITY",
        signer_key_ids=["key-policy-01"],
    )
    store.append_entry(e2)

    suspend_decision = gate.evaluate_release(subject)
    assert suspend_decision.allowed is False
    assert suspend_decision.decision == "DENY"
    assert suspend_decision.effective_state == "SUSPENDED"
    assert suspend_decision.rollback_running_workloads is False

    # 4. Append dual-role human quorum REVOKED entry -> Gate permanently DENIES, history preserved
    e2_hash = hashlib.sha256(e2["canonical_payload_b64"].encode("ascii")).hexdigest()
    e3 = build_signed_entry(
        key_ring,
        seq=3,
        prev_sha256=e2_hash,
        cert_id=cert_id,
        from_state="SUSPENDED",
        to_state="REVOKED",
        trigger_class="CRITICAL_VULNERABILITY",
        signer_key_ids=["key-sec-01", "key-gov-01"],
        mode="HUMAN_QUORUM",
        quorum="2-OF-N-DUAL-ROLE",
    )
    store.append_entry(e3)

    revoke_decision = gate.evaluate_release(subject)
    assert revoke_decision.allowed is False
    assert revoke_decision.effective_state == "REVOKED"
    assert revoke_decision.latest_sequence_number == 3

    # All 3 historical entries remain intact in the append-only ledger
    history = store.get_entries_for_certification(cert_id)
    assert [item["payload"]["transition"]["to_state"] for item in history] == [
        "CERTIFIED",
        "SUSPENDED",
        "REVOKED",
    ]


def test_store_rejects_invalid_entry_without_mutating_ledger(tmp_path: Path, validator, key_ring):  # noqa: F811
    ledger_file = tmp_path / "trust_registry.jsonl"
    store = AppendOnlyTrustStore(ledger_path=ledger_file, validator=validator)

    cert_id = str(uuid.uuid4())
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
    store.append_entry(e1)

    # Attempt to append an un-quorumed REVOKED entry
    e1_hash = hashlib.sha256(e1["canonical_payload_b64"].encode("ascii")).hexdigest()
    bad_e2 = build_signed_entry(
        key_ring,
        seq=2,
        prev_sha256=e1_hash,
        cert_id=cert_id,
        from_state="CERTIFIED",
        to_state="REVOKED",
        trigger_class="EVIDENCE_FALSIFIED",
        signer_key_ids=["key-policy-01"],  # Missing 2-of-N human quorum
    )

    with pytest.raises(TrustValidationError, match="Human quorum requires"):
        store.append_entry(bad_e2)

    # Ledger still contains only the 1 valid genesis entry
    assert len(store.get_entries_for_certification(cert_id)) == 1


def test_store_detects_on_disk_tampering_on_read(tmp_path: Path, validator, key_ring):  # noqa: F811
    ledger_file = tmp_path / "trust_registry.jsonl"
    store = AppendOnlyTrustStore(ledger_path=ledger_file, validator=validator)

    cert_id = str(uuid.uuid4())
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
    store.append_entry(e1)

    # Corrupt a byte on disk directly
    corrupted = ledger_file.read_text(encoding="utf-8").replace("TEST_TRANSITION_EVENT", "HACKED_EVENT")
    ledger_file.write_text(corrupted, encoding="utf-8")

    with pytest.raises(TrustValidationError, match="does not match RFC 8785 JCS"):
        store.get_snapshot(cert_id)