from aivas.scorer import score_findings


def _f(cve_id, cvss, sev="HIGH", conf="confirmed", kev=False):
    return {
        "cve_id": cve_id, "cvss_score": cvss, "cvss_severity": sev,
        "confidence": conf, "kev": kev,
    }


def test_no_findings_grade_a_100():
    assert score_findings([])["grade"] == "A"
    assert score_findings([])["score"] == 100


def test_single_non_kev_critical_grade_unchanged():
    out = score_findings([_f("CVE-1", 9.5, sev="CRITICAL")])
    # CRITICAL with confirmed conf → weight 15 × 1.0 = 15 penalty → 85
    assert out["grade"] in ("B", "A")
    assert out["score"] <= 90


def test_kev_finding_caps_grade_at_c():
    # One LOW finding marked KEV would otherwise score very high
    out = score_findings([_f("CVE-K", 3.0, sev="LOW", kev=True)])
    assert out["grade"] in ("C", "D", "F")
    assert out["score"] <= 75


def test_kev_multiplier_increases_penalty():
    base = score_findings([_f("CVE-1", 7.0, sev="HIGH", conf="confirmed", kev=False)])
    with_kev = score_findings([_f("CVE-1", 7.0, sev="HIGH", conf="confirmed", kev=True)])
    assert with_kev["score"] < base["score"]


def test_kev_does_not_demote_below_natural_grade():
    """If grade is already D or F, KEV cap leaves it as-is."""
    findings = [_f(f"CVE-{i}", 10.0, sev="CRITICAL", kev=True) for i in range(5)]
    out = score_findings(findings)
    assert out["grade"] == "F"


def test_kev_multiple_findings_compound():
    one_kev = score_findings([
        _f("CVE-1", 9.0, sev="CRITICAL", kev=True),
        _f("CVE-2", 5.0, sev="MEDIUM", kev=False),
    ])
    two_kev = score_findings([
        _f("CVE-1", 9.0, sev="CRITICAL", kev=True),
        _f("CVE-2", 5.0, sev="MEDIUM", kev=True),
    ])
    assert two_kev["score"] <= one_kev["score"]


def test_sev_counts_still_count_all_findings():
    findings = [
        _f("CVE-1", 9.0, sev="CRITICAL"),
        _f("CVE-2", 5.0, sev="MEDIUM"),
        _f("CVE-3", 3.0, sev="LOW"),
    ]
    out = score_findings(findings)
    assert out["sev_counts"].get("CRITICAL") == 1
    assert out["sev_counts"].get("MEDIUM") == 1
    assert out["sev_counts"].get("LOW") == 1
