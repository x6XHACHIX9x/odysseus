import base64
import hashlib
import uuid
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from odysseus.trust.validator import (
    TrustedKey,
    TrustRegistryValidator,
    TrustValidationError,
)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture()
def key_ring():
    # Generate ephemeral keys for testing
    policy_priv = ed25519.Ed25519PrivateKey.generate()
    sec_priv = ec.generate_private_key(ec.SECP256R1())
    gov_priv = ec.generate_private_key(ec.SECP256R1())
    orig_gov_priv = ec.generate_private_key(ec.SECP256R1())

    def to_pem(priv_key) -> bytes:
        return priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    trusted = {
        "key-policy-01": TrustedKey("key-policy-01", "POLICY_ENGINE", "ED25519", to_pem(policy_priv)),
        "key-sec-01": TrustedKey("key-sec-01", "SECURITY_AUTHORITY", "ECDSA-P256-SHA256", to_pem(sec_priv)),
        "key-gov-01": TrustedKey("key-gov-01", "GOVERNANCE_AUTHORITY", "ECDSA-P256-SHA256", to_pem(gov_priv)),
        "key-gov-orig": TrustedKey("key-gov-orig", "GOVERNANCE_AUTHORITY", "ECDSA-P256-SHA256", to_pem(orig_gov_priv)),
    }
    private_keys = {
        "key-policy-01": policy_priv,
        "key-sec-01": sec_priv,
        "key-gov-01": gov_priv,
        "key-gov-orig": orig_gov_priv,
    }
    return trusted, private_keys


@pytest.fixture()
def validator(key_ring):
    trusted, _ = key_ring
    schema_path = Path("schemas/ops-v3-203/trust-registry-entry.v1.json")
    return TrustRegistryValidator(schema_path=schema_path, trusted_keys=trusted)


def build_signed_entry(
    key_ring,
    *,
    seq: int,
    prev_sha256: str,
    cert_id: str,
    from_state: str,
    to_state: str,
    trigger_class: str,
    signer_key_ids: list[str],
    original_certifiers: list[str] | None = None,
    mode: str = "AUTOMATED_POLICY_ENGINE",
    quorum: str = "1-OF-1-SYSTEM",
) -> dict:
    trusted, private_keys = key_ring
    payload = {
        "entry_id": str(uuid.uuid4()),
        "sequence_number": seq,
        "prev_entry_sha256": prev_sha256,
        "timestamp_utc": "2026-11-13T19:50:12Z",
        "certification_id": cert_id,
        "subject_binding": {
            "artifact_sha256": "a" * 64,
            "sbom_sha256": "b" * 64,
            "environment_baseline_sha256": "c" * 64,
            "ops_v3_202_challenge_nonce": "nonce-" + ("d" * 32),
        },
        "transition": {
            "from_state": from_state,
            "to_state": to_state,
            "trigger_class": trigger_class,
            "reason_code": "TEST_TRANSITION_EVENT",
            "evidence_refs": [
                {
                    "uri": "https://odyai.internal/evidence/item-1.json",
                    "sha256": "e" * 64,
                    "media_type": "application/json",
                }
            ],
        },
        "authorization": {
            "mode": mode,
            "required_quorum": quorum,
            "original_certifier_ids": original_certifiers or ["key-gov-orig"],
        },
    }

    canonical_bytes = rfc8785.dumps(payload)
    canonical_b64 = b64url_encode(canonical_bytes)

    signatures = []
    for kid in signer_key_ids:
        meta = trusted[kid]
        priv = private_keys[kid]
        if meta.algorithm == "ED25519":
            raw_sig = priv.sign(canonical_bytes)
            webauthn = None
        else:
            raw_sig = priv.sign(canonical_bytes, ec.ECDSA(hashes.SHA256()))
            webauthn = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAKg=="

        signatures.append(
            {
                "signer_id": f"{kid}@odyai.internal",
                "role": meta.role,
                "key_id": kid,
                "algorithm": meta.algorithm,
                "webauthn_authenticator_data": webauthn,
                "signature_b64": b64url_encode(raw_sig),
            }
        )

    return {
        "envelope_version": "1.0.0",
        "payload_type": "application/vnd.odyai.trust-transition+json",
        "canonical_payload_b64": canonical_b64,
        "payload": payload,
        "signatures": signatures,
    }


def test_valid_lifecycle_chain_and_human_revocation(validator, key_ring):
    cert_id = str(uuid.uuid4())

    # 1. Genesis: PENDING -> CERTIFIED
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
    validator.validate_entry(e1, previous_entry=None)

    # 2. Automated containment: CERTIFIED -> SUSPENDED
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
    validator.validate_entry(e2, previous_entry=e1)

    # 3. Dual-role human quorum: SUSPENDED -> REVOKED
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
    validator.validate_entry(e3, previous_entry=e2)


def test_sod_violation_blocks_original_certifier_from_clearing_suspension(validator, key_ring):
    cert_id = str(uuid.uuid4())
    entry = build_signed_entry(
        key_ring,
        seq=1,
        prev_sha256="0" * 64,
        cert_id=cert_id,
        from_state="SUSPENDED",
        to_state="CERTIFIED",
        trigger_class="DISPUTE_RESOLUTION",
        signer_key_ids=["key-sec-01", "key-gov-orig"],
        original_certifiers=["key-gov-orig"],
        mode="HUMAN_QUORUM",
        quorum="2-OF-N-DUAL-ROLE",
    )
    with pytest.raises(TrustValidationError, match="Separation of Duties violation"):
        validator.validate_entry(entry, previous_entry=None)


def test_tampered_payload_fails_closed(validator, key_ring):
    entry = build_signed_entry(
        key_ring,
        seq=1,
        prev_sha256="0" * 64,
        cert_id=str(uuid.uuid4()),
        from_state="PENDING",
        to_state="CERTIFIED",
        trigger_class="VALIDATION_PASS",
        signer_key_ids=["key-policy-01"],
    )
    # Tamper with reason_code after signing
    entry["payload"]["transition"]["reason_code"] = "TAMPERED_REASON"
    with pytest.raises(TrustValidationError, match="does not match RFC 8785 JCS"):
        validator.validate_entry(entry, previous_entry=None)


def test_broken_hash_chain_fails_closed(validator, key_ring):
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
    e2 = build_signed_entry(
        key_ring,
        seq=2,
        prev_sha256="f" * 64,  # Wrong hash link
        cert_id=cert_id,
        from_state="CERTIFIED",
        to_state="SUSPENDED",
        trigger_class="KEY_COMPROMISE",
        signer_key_ids=["key-policy-01"],
    )
    with pytest.raises(TrustValidationError, match="Hash chain broken"):
        validator.validate_entry(e2, previous_entry=e1)
