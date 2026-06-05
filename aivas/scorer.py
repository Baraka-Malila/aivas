_WEIGHTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}
_CONFIDENCE_MULT = {"confirmed": 1.0, "probable": 0.9, "possible": 0.5}
_MAX_PER_FINDING = 20


def score_findings(findings: list[dict]) -> dict:
    penalty = 0.0
    for f in findings:
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
    return {"score": score, "grade": grade, "penalty": int(penalty)}
