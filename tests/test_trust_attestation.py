import base64
import uuid
import rfc8785
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import pytest

from odysseus.trust.attestation import (
    AttestationValidationError,
    AttesterKey,
    PolicySignerConfig,
    RuntimeAttestationVerifier,
)
from odysseus.trust.gate import ReleaseGateVerifier, SubjectSpec
from odysseus.trust.store import AppendOnlyTrustStore
from odysseus.trust.validator import TrustRegistryValidator
from tests.test_trust_validator import build_signed_entry, key_ring  # noqa: F401


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _build_attestation_report(
    attester_priv: ed25519.Ed25519PrivateKey,
    *,
    cert_id: str,
    epoch_seq: int,
    epoch_nonce: str,
    observed_artifact: str = "a" * 64,
    observed_sbom: str = "b" * 64,
    observed_env: str = "c" * 64,
    status: str = "HEALTHY",
    mismatched_fields: list[str] | None = None,
    recommended_trigger: str | None = None,
) -> dict:
    payload = {
        "report_id": str(uuid.uuid4()),
        "timestamp_utc": "2026-11-13T20:45:00Z",
        "certification_id": cert_id,
        "workload_identity": {
            "spiffe_id": "spiffe://odyai.internal/ns/prod/sa/odysseus-worker",
            "node_id": "enclave-node-01",
            "enclave_type": "AWS_NITRO",
            "hardware_quote_sha256": "9" * 64,
        },
        "epoch_attestation": {
            "epoch_sequence": epoch_seq,
            "epoch_nonce": epoch_nonce,
            "interval_seconds": 60,
        },
        "certified_binding": {
            "artifact_sha256": "a" * 64,
            "sbom_sha256": "b" * 64,
            "environment_baseline_sha256": "c" * 64,
            "ops_v3_202_challenge_nonce": "nonce-" + ("d" * 32),
        },
        "observed_measurements": {
            "artifact_sha256": observed_artifact,
            "sbom_sha256": observed_sbom,
            "environment_baseline_sha256": observed_env,
        },
        "evaluation": {
            "status": status,
            "mismatched_fields": mismatched_fields or [],
            "recommended_trigger_class": recommended_trigger,
        },
    }
    canonical = rfc8785.dumps(payload)
    return {
        "envelope_version": "1.0.0",
        "payload_type": "application/vnd.odyai.runtime-attestation+json",
        "canonical_payload_b64": _b64(canonical),
        "payload": payload,
        "signature": {
            "attester_id": "nitro-enclave-01",
            "key_id": "attester-nitro-01",
            "algorithm": "ED25519",
            "signature_b64": _b64(attester_priv.sign(canonical)),
        },
    }


@pytest.fixture()
def attestation_harness(tmp_path: Path, key_ring):  # noqa: F811
    trusted, private_keys = key_ring
    now = datetime(2026, 11, 13, 20, 45, 0, tzinfo=timezone.utc)

    validator = TrustRegistryValidator(
        schema_path=Path("schemas/ops-v3-203/trust-registry-entry.v1.json"),
        trusted_keys=trusted,
    )
    store = AppendOnlyTrustStore(
        ledger_path=tmp_path / "trust_ledger.jsonl",
        validator=validator,
        clock=lambda: now,
    )
    gate = ReleaseGateVerifier(
        validator=validator,
        fetch_snapshot=store.get_snapshot,
        clock=lambda: now,
    )

    attester_priv = ed25519.Ed25519PrivateKey.generate()
    attester_pub_pem = attester_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    policy_priv_pem = private_keys["key-policy-01"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    verifier = RuntimeAttestationVerifier(
        schema_path=Path("schemas/ops-v3-204/runtime-attestation.v1.json"),
        attester_keys={
            "attester-nitro-01": AttesterKey(
                key_id="attester-nitro-01",
                algorithm="ED25519",
                public_key_pem=attester_pub_pem,
            )
        },
        store=store,
        policy_signer=PolicySignerConfig(
            key_id="key-policy-01",
            signer_id="policy-engine@odyai.internal",
            algorithm="ED25519",
            private_key_pem=policy_priv_pem,
        ),
        clock=lambda: now,
    )

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

    subject = SubjectSpec(
        certification_id=cert_id,
        artifact_sha256="a" * 64,
        sbom_sha256="b" * 64,
        environment_baseline_sha256="c" * 64,
        ops_v3_202_challenge_nonce="nonce-" + ("d" * 32),
    )
    return verifier, gate, store, attester_priv, cert_id, subject


def test_healthy_heartbeat_keeps_certification_active(attestation_harness):
    verifier, gate, _, attester_priv, cert_id, subject = attestation_harness
    nonce = "epoch-nonce-" + ("1" * 32)
    report = _build_attestation_report(attester_priv, cert_id=cert_id, epoch_seq=1, epoch_nonce=nonce)

    res = verifier.process_report(report, expected_epoch_nonce=nonce)
    assert res.status == "HEALTHY"
    assert res.suspension_triggered is False

    decision = gate.evaluate_release(subject)
    assert decision.allowed is True
    assert decision.effective_state == "CERTIFIED"


def test_runtime_drift_automatically_suspends_certification_and_blocks_gate(attestation_harness):
    verifier, gate, store, attester_priv, cert_id, subject = attestation_harness
    nonce = "epoch-nonce-" + ("2" * 32)
    report = _build_attestation_report(
        attester_priv,
        cert_id=cert_id,
        epoch_seq=2,
        epoch_nonce=nonce,
        observed_env="f" * 64,
        status="DRIFT_DETECTED",
        mismatched_fields=["environment_baseline_sha256"],
        recommended_trigger="ENVIRONMENT_DRIFT",
    )

    res = verifier.process_report(report, expected_epoch_nonce=nonce)
    assert res.status == "DRIFT_DETECTED"
    assert res.mismatched_fields == ("environment_baseline_sha256",)
    assert res.suspension_triggered is True
    assert res.trigger_class == "ENVIRONMENT_DRIFT"

    decision = gate.evaluate_release(subject)
    assert decision.allowed is False
    assert decision.decision == "DENY"
    assert decision.effective_state == "SUSPENDED"
    assert decision.rollback_running_workloads is False

    entries = store.get_entries_for_certification(cert_id)
    assert len(entries) == 2
    assert entries[-1]["payload"]["transition"]["trigger_class"] == "ENVIRONMENT_DRIFT"


def test_epoch_nonce_replay_triggers_tamper_suspension(attestation_harness):
    verifier, gate, _, attester_priv, cert_id, subject = attestation_harness
    expected_nonce = "epoch-nonce-" + ("3" * 32)
    stale_nonce = "stale-nonce-" + ("9" * 32)

    report = _build_attestation_report(
        attester_priv,
        cert_id=cert_id,
        epoch_seq=3,
        epoch_nonce=stale_nonce,
    )

    res = verifier.process_report(report, expected_epoch_nonce=expected_nonce)
    assert res.status == "TAMPER_DETECTED"
    assert "epoch_nonce" in res.mismatched_fields
    assert res.suspension_triggered is True
    assert res.trigger_class == "TAMPER_OR_REPLAY"

    decision = gate.evaluate_release(subject)
    assert decision.allowed is False
    assert decision.effective_state == "SUSPENDED"


def test_forged_attester_signature_rejected_before_ledger_mutation(attestation_harness):
    verifier, _, store, _, cert_id, _ = attestation_harness
    rogue_priv = ed25519.Ed25519PrivateKey.generate()
    nonce = "epoch-nonce-" + ("4" * 32)
    forged = _build_attestation_report(rogue_priv, cert_id=cert_id, epoch_seq=4, epoch_nonce=nonce)

    with pytest.raises(AttestationValidationError, match="Invalid attestation signature"):
        verifier.process_report(forged, expected_epoch_nonce=nonce)

    assert len(store.get_entries_for_certification(cert_id)) == 1
