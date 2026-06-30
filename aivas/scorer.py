_WEIGHTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}
_CONFIDENCE_MULT = {"confirmed": 1.0, "probable": 0.9, "possible": 0.5}
_MAX_PER_FINDING = 20
_SCORE_TOP_N = 5


def score_findings(findings: list[dict]) -> dict:
    top = sorted(findings, key=lambda f: f.get("cvss_score") or 0, reverse=True)[:_SCORE_TOP_N]
    penalty = 0.0
    for f in top:
        sev = f.get("cvss_severity") or ""
        conf = f.get("confidence") or "possible"
        weight = _WEIGHTS.get(sev, 0)
        mult = _CONFIDENCE_MULT.get(conf, 0.5)
        penalty += min(weight * mult, _MAX_PER_FINDING)
    score = max(0, 100 - int(penalty))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    sev_counts = {}
    for f in findings:
        s = (f.get("cvss_severity") or "N/A").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    return {
        "score": score,
        "grade": grade,
        "penalty": int(penalty),
        "total": len(findings),
        "sev_counts": sev_counts,
    }
