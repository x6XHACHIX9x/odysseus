import hashlib
import json
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from odysseus.trust.cli import main
from tests.test_trust_validator import build_signed_entry, key_ring  # noqa: F401


@pytest.fixture()
def cli_env(tmp_path: Path, key_ring):  # noqa: F811
    trusted, private_keys = key_ring
    keys_file = tmp_path / "keyring.json"
    ledger_file = tmp_path / "ledger.jsonl"

    keys_payload = {
        "keys": [
            {
                "key_id": tk.key_id,
                "role": tk.role,
                "algorithm": tk.algorithm,
                "public_key_pem": tk.public_key_pem.decode("utf-8"),
            }
            for tk in trusted.values()
        ]
    }
    keys_file.write_text(json.dumps(keys_payload, indent=2), encoding="utf-8")

    priv_paths: dict[str, Path] = {}
    for kid, priv in private_keys.items():
        pem_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        p = tmp_path / f"{kid}.priv.pem"
        p.write_bytes(pem_bytes)
        priv_paths[kid] = p

    return tmp_path, keys_file, ledger_file, key_ring, priv_paths


def test_cli_sign_entry_end_to_end_quorum_revocation(cli_env, capsys):
    tmp_path, keys_file, ledger_file, _, priv_paths = cli_env
    cert_id = str(uuid.uuid4())
    base_args = [
        "--schema",
        "schemas/ops-v3-203/trust-registry-entry.v1.json",
        "--keys",
        str(keys_file),
        "--ledger",
        str(ledger_file),
    ]

    # 1. sign-entry --append for genesis PENDING -> CERTIFIED
    rc = main(
        [
            *base_args,
            "sign-entry",
            "--certification-id",
            cert_id,
            "--from-state",
            "PENDING",
            "--to-state",
            "CERTIFIED",
            "--trigger-class",
            "VALIDATION_PASS",
            "--reason-code",
            "OPS_V3_202_PASS",
            "--evidence-uri",
            "https://odyai.internal/evidence/1.json",
            "--evidence-sha256",
            "e" * 64,
            "--artifact-sha256",
            "a" * 64,
            "--sbom-sha256",
            "b" * 64,
            "--environment-baseline-sha256",
            "c" * 64,
            "--challenge-nonce",
            "nonce-" + ("d" * 32),
            "--signer",
            f"key-policy-01|policy@odyai.internal|{priv_paths['key-policy-01']}",
            "--append",
        ]
    )
    assert rc == 0
    s1 = json.loads(capsys.readouterr().out)
    assert s1["status"] == "SIGNED_AND_APPENDED"
    assert s1["sequence_number"] == 1

    # 2. sign-entry --append for automated CERTIFIED -> SUSPENDED (inherits subject binding automatically)
    rc = main(
        [
            *base_args,
            "sign-entry",
            "--certification-id",
            cert_id,
            "--from-state",
            "CERTIFIED",
            "--to-state",
            "SUSPENDED",
            "--trigger-class",
            "CRITICAL_VULNERABILITY",
            "--reason-code",
            "CVE_2026_99999_MATCH",
            "--evidence-uri",
            "https://odyai.internal/evidence/2.json",
            "--evidence-sha256",
            "f" * 64,
            "--signer",
            f"key-policy-01|policy@odyai.internal|{priv_paths['key-policy-01']}",
            "--append",
        ]
    )
    assert rc == 0
    s2 = json.loads(capsys.readouterr().out)
    assert s2["sequence_number"] == 2

    # 3. sign-entry --append for dual-role human quorum SUSPENDED -> REVOKED
    webauthn_b64 = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAKg=="
    rc = main(
        [
            *base_args,
            "sign-entry",
            "--certification-id",
            cert_id,
            "--from-state",
            "SUSPENDED",
            "--to-state",
            "REVOKED",
            "--trigger-class",
            "CRITICAL_VULNERABILITY",
            "--reason-code",
            "CONFIRMED_EXPLOITABLE_RCE",
            "--evidence-uri",
            "https://odyai.internal/evidence/3.json",
            "--evidence-sha256",
            "1" * 64,
            "--auth-mode",
            "HUMAN_QUORUM",
            "--required-quorum",
            "2-OF-N-DUAL-ROLE",
            "--signer",
            f"key-sec-01|sec@odyai.internal|{priv_paths['key-sec-01']}|{webauthn_b64}",
            "--signer",
            f"key-gov-01|gov@odyai.internal|{priv_paths['key-gov-01']}|{webauthn_b64}",
            "--append",
        ]
    )
    assert rc == 0
    s3 = json.loads(capsys.readouterr().out)
    assert s3["sequence_number"] == 3

    # 4. Verify full 3-entry ledger integrity & gate denial
    assert main([*base_args, "verify-ledger"]) == 0
    verify_out = json.loads(capsys.readouterr().out)
    assert verify_out["verified_entries"] == 3

    gate_rc = main(
        [
            *base_args,
            "gate-check",
            "--certification-id",
            cert_id,
            "--artifact-sha256",
            "a" * 64,
            "--sbom-sha256",
            "b" * 64,
            "--environment-baseline-sha256",
            "c" * 64,
            "--challenge-nonce",
            "nonce-" + ("d" * 32),
        ]
    )
    assert gate_rc == 1
    gate_out = json.loads(capsys.readouterr().out)
    assert gate_out["effective_state"] == "REVOKED"
    assert gate_out["rollback_running_workloads"] is False


def test_cli_full_workflow_append_verify_inspect_and_gate_check(cli_env, capsys):
    tmp_path, keys_file, ledger_file, key_ring, _ = cli_env
    cert_id = str(uuid.uuid4())
    base_args = [
        "--schema",
        "schemas/ops-v3-203/trust-registry-entry.v1.json",
        "--keys",
        str(keys_file),
        "--ledger",
        str(ledger_file),
    ]

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
    e1_file = tmp_path / "e1.json"
    e1_file.write_text(json.dumps(e1), encoding="utf-8")

    rc = main([*base_args, "append", "--entry", str(e1_file)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "APPENDED"

    gate_args = [
        *base_args,
        "gate-check",
        "--certification-id",
        cert_id,
        "--artifact-sha256",
        "a" * 64,
        "--sbom-sha256",
        "b" * 64,
        "--environment-baseline-sha256",
        "c" * 64,
        "--challenge-nonce",
        "nonce-" + ("d" * 32),
    ]
    assert main(gate_args) == 0
    assert json.loads(capsys.readouterr().out)["allowed"] is True

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
    e2_file = tmp_path / "e2.json"
    e2_file.write_text(json.dumps(e2), encoding="utf-8")
    assert main([*base_args, "append", "--entry", str(e2_file)]) == 0
    capsys.readouterr()

    assert main(gate_args) == 1
    deny_out = json.loads(capsys.readouterr().out)
    assert deny_out["effective_state"] == "SUSPENDED"
    assert deny_out["rollback_running_workloads"] is False

    assert main([*base_args, "inspect", "--certification-id", cert_id]) == 0
    inspect_out = json.loads(capsys.readouterr().out)
    assert inspect_out["transition_count"] == 2


def test_cli_verify_ledger_fails_closed_on_tampering(cli_env, capsys):
    tmp_path, keys_file, ledger_file, key_ring, _ = cli_env
    cert_id = str(uuid.uuid4())
    base_args = [
        "--schema",
        "schemas/ops-v3-203/trust-registry-entry.v1.json",
        "--keys",
        str(keys_file),
        "--ledger",
        str(ledger_file),
    ]

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
    e1_file = tmp_path / "e1.json"
    e1_file.write_text(json.dumps(e1), encoding="utf-8")
    assert main([*base_args, "append", "--entry", str(e1_file)]) == 0
    capsys.readouterr()

    ledger_file.write_text(
        ledger_file.read_text(encoding="utf-8").replace("TEST_TRANSITION_EVENT", "ALTERED_EVENT"),
        encoding="utf-8",
    )

    assert main([*base_args, "verify-ledger"]) == 1
    assert json.loads(capsys.readouterr().err)["status"] == "FAIL_CLOSED"