from aivas.tui.colors import ACCENT, SEVERITY_COLORS, GRADE_COLOR, KEV_BADGE


def test_accent_is_blue():
    assert ACCENT == "#4a9eff"


def test_severity_has_four_keys():
    assert set(SEVERITY_COLORS.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_critical_is_red():
    assert "e53935" in SEVERITY_COLORS["CRITICAL"]


def test_high_is_orange():
    assert "ff6d00" in SEVERITY_COLORS["HIGH"]


def test_grade_color_df_is_red():
    assert "e53935" in GRADE_COLOR("F")
    assert "e53935" in GRADE_COLOR("D")


def test_grade_color_ab_is_green():
    assert "4caf50" in GRADE_COLOR("A")
    assert "4caf50" in GRADE_COLOR("B")


def test_grade_color_c_is_gold():
    assert "fdd835" in GRADE_COLOR("C")
