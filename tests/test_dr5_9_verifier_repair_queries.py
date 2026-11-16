"""Tests for DR-5.9 verifier-guided repair & historical follow-up query refinement."""

from src.research_verifier import (
    _DOMAIN_FOLLOWUP_GAP_VERDICTS,
    _DOMAIN_FOLLOWUP_TEMPLATES,
    _EVIDENCE_CLASSIFICATION_FOLLOWUP_TEMPLATES,
    _build_domain_followup_queries,
    verify_report_evidence,
)


def test_gap_verdicts_has_no_typo_and_covers_canonical_states():
    assert "CONFLICTING_EVIDENGE" not in _DOMAIN_FOLLOWUP_GAP_VERDICTS
    assert _DOMAIN_FOLLOWUP_GAP_VERDICTS == frozenset({
        "CONTESTED",
        "INSUFFICIENT_EVIDENCE",
        "UNSUPPORTED",
        "CONFLICTING_EVIDENCE",
    })


def test_historical_domain_uses_historical_archive_template():
    assert "historical" in _DOMAIN_FOLLOWUP_TEMPLATES
    assessments = [
        {
            "domain": "historical",
            "claim_assessment": "CONTESTED",
            "claim_text": "The Treaty of Westphalia established territorial sovereignty in Europe.",
        }
    ]
    queries = _build_domain_followup_queries(assessments)
    assert len(queries) == 1
    assert "primary historical archive contemporaneous chronicle official record" in queries[0]
    assert "primary source official verification" not in queries[0]


def test_evidence_classification_overrides_generic_domain_template():
    cases = [
        ("historical", "UNDATED_HISTORICAL_CLAIM", "exact year date BCE CE primary historical chronicle"),
        ("historical", "JULIAN_GREGORIAN_CALENDAR_MISMATCH", "Julian Old Style Gregorian New Style calendar date"),
        ("historical", "ANACHRONISTIC_POLITY_ATTRIBUTION", "founding date historical polity contemporaneous name"),
        ("historical", "DISCREDITED_OR_FORGED_SOURCE", "authentic primary archive critical edition historiography"),
        ("financial", "GAAP_NON_GAAP_MISMATCH", "GAAP reconciliation SEC 10-K 10-Q filing"),
        ("legal", "SUPERSEDED_OR_REPEALED_STATUTE", "current codified statute effective date amendment"),
        ("legal", "CURRENT_STATUS_NOT_ESTABLISHED", "enacted statute effective date official code"),
        ("medical", "PREPRINT_NOT_PEER_REVIEWED", "peer reviewed journal publication clinical trial"),
    ]
    for domain, ev_class, expected_phrase in cases:
        assert ev_class in _EVIDENCE_CLASSIFICATION_FOLLOWUP_TEMPLATES
        queries = _build_domain_followup_queries([
            {
                "domain": domain,
                "claim_assessment": "INSUFFICIENT_EVIDENCE",
                "evidence_classification": ev_class,
                "claim_text": "Specific empirical claim requiring targeted repair verification.",
            }
        ])
        assert len(queries) == 1
        assert expected_phrase in queries[0]


def test_redacted_claims_and_duplicates_are_suppressed_with_max_total_cap():
    assessments = [
        {
            "domain": "historical",
            "claim_assessment": "UNSUPPORTED",
            "claim_text": "Archival record [REDACTED_ID] should never leak into search queries.",
        },
        {
            "domain": "historical",
            "claim_assessment": "CONTESTED",
            "claim_text": "Battle of Thermopylae troop strength estimates vary widely.",
        },
        {
            "domain": "historical",
            "claim_assessment": "CONFLICTING_EVIDENCE",
            "claim_text": "Battle of Thermopylae troop strength estimates vary widely!",
        },
        {
            "domain": "financial",
            "claim_assessment": "CONTESTED",
            "claim_text": "Acme Corp reported Q4 2025 operating margin expansion.",
        },
        {
            "domain": "legal",
            "claim_assessment": "INSUFFICIENT_EVIDENCE",
            "claim_text": "Section 230 statutory immunity scope under federal precedent.",
        },
        {
            "domain": "medical",
            "claim_assessment": "UNSUPPORTED",
            "claim_text": "Phase 3 randomized trial primary endpoint reduction.",
        },
        {
            "domain": "technical",
            "claim_assessment": "CONTESTED",
            "claim_text": "NVMe queue depth latency benchmark results.",
        },
    ]
    queries = _build_domain_followup_queries(assessments, max_total=4)
    assert len(queries) == 4
    assert all("[REDACTED" not in q for q in queries)
    assert sum("Battle of Thermopylae" in q for q in queries) == 1


def test_end_to_end_verify_report_evidence_dr5_8_to_dr5_9_followup():
    report = (
        "## Historical Overview\n"
        "According to ancient chronicles, the Council of Nicaea convened and promulgated the Nicene Creed.\n"
    )
    findings = [
        {
            "url": "https://archive.example.org/nicaea-record",
            "title": "Early Church Councils Chronicle",
            "snippet": "The Council of Nicaea debated Christological formulations and issued creedal canons.",
        }
    ]
    vr = verify_report_evidence(
        report,
        findings,
        enable_domain_verifiers=True,
        category="historical",
    )
    assert vr.followup_queries
    assert any(
        "exact year date BCE CE primary historical chronicle" in q
        or "primary historical archive contemporaneous chronicle official record" in q
        for q in vr.followup_queries
    )
