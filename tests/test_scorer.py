from aivas.scorer import score_findings

CRITICAL_CONFIRMED = [
    {"cvss_severity": "CRITICAL", "confidence": "confirmed"},
    {"cvss_severity": "CRITICAL", "confidence": "confirmed"},
]
HIGH_PROBABLE = [{"cvss_severity": "HIGH", "confidence": "probable"}]


def test_score_empty_findings_is_100_grade_A():
    result = score_findings([])
    assert result["score"] == 100
    assert result["grade"] == "A"


def test_score_two_critical_confirmed_lowers_score():
    result = score_findings(CRITICAL_CONFIRMED)
    # 2x CRITICAL confirmed: penalty = 2 * min(15*1.0, 20) = 30 → score = 70
    assert result["score"] == 70
    assert result["grade"] == "C"


def test_score_single_high_probable():
    result = score_findings(HIGH_PROBABLE)
    # penalty = min(8 * 0.9, 20) = 7.2 → int(7.2) = 7 → score = 93
    assert result["score"] == 93
    assert result["grade"] == "A"


def test_score_returns_required_keys():
    result = score_findings(HIGH_PROBABLE)
    assert "score" in result
    assert "grade" in result
    assert "penalty" in result


def test_score_grade_F_with_many_criticals():
    many = [{"cvss_severity": "CRITICAL", "confidence": "confirmed"}] * 5
    assert score_findings(many)["grade"] == "F"


def test_score_grade_A_with_one_low():
    one_low = [{"cvss_severity": "LOW", "confidence": "confirmed"}]
    assert score_findings(one_low)["grade"] == "A"
