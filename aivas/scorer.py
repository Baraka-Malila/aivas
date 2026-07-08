_WEIGHTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}
_CONFIDENCE_MULT = {"confirmed": 1.0, "probable": 0.9, "possible": 0.5}
_MAX_PER_FINDING = 20
_SCORE_TOP_N = 5
_KEV_MULT = 1.5
_KEV_GRADE_CAP_SCORE = 74


def _penalty_for(f: dict) -> float:
    sev = f.get("cvss_severity") or ""
    conf = f.get("confidence") or "possible"
    weight = _WEIGHTS.get(sev, 0)
    mult = _CONFIDENCE_MULT.get(conf, 0.5)
    base = weight * mult
    if f.get("kev"):
        base *= _KEV_MULT
    return min(base, _MAX_PER_FINDING)


def _grade_for_score(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def score_findings(findings: list[dict]) -> dict:
    # Sort by effective penalty (not raw CVSS) so KEV-multiplied findings rank
    # higher than same-severity non-KEV ones.  Compute penalty once per finding
    # to avoid calling _penalty_for twice (during sort and during sum).
    top_with_pen = sorted(
        ((f, _penalty_for(f)) for f in findings),
        key=lambda x: x[1],
        reverse=True,
    )[:_SCORE_TOP_N]
    top = [f for f, _ in top_with_pen]
    penalty = sum(min(p, _MAX_PER_FINDING) for _, p in top_with_pen)
    score = max(0, 100 - int(penalty))
    grade = _grade_for_score(score)

    # KEV cap: any KEV finding caps grade at C (score ≤ 74)
    if any(f.get("kev") for f in findings):
        if score > _KEV_GRADE_CAP_SCORE:
            score = _KEV_GRADE_CAP_SCORE
            grade = _grade_for_score(score)

    sev_counts: dict = {}
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
