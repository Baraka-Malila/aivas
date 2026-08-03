from aivas.scanner.nse import scripts_for_level, QUICK_SCRIPTS, FULL_SCRIPTS


def test_level_1_returns_quick_scripts():
    assert scripts_for_level(1) == QUICK_SCRIPTS


def test_level_2_returns_full_scripts():
    assert scripts_for_level(2) == FULL_SCRIPTS


def test_level_3_returns_full_scripts():
    assert scripts_for_level(3) == FULL_SCRIPTS


def test_quick_scripts_is_subset_of_full():
    quick = set(QUICK_SCRIPTS.split(","))
    full = set(FULL_SCRIPTS.split(","))
    assert quick.issubset(full)


def test_full_scripts_includes_tls_checks():
    for script in ("ssl-enum-ciphers", "ssl-cert", "http-security-headers"):
        assert script in FULL_SCRIPTS, f"{script} missing from FULL_SCRIPTS"
