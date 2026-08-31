"""Default severities must agree between the check classes and DEFAULT_CONFIG."""

from iam_validator.core.check_registry import create_default_registry
from iam_validator.core.config.defaults import DEFAULT_CONFIG

VALID_SEVERITIES = {"critical", "high", "medium", "low", "error", "warning", "none"}


def test_class_default_severity_matches_default_config():
    mismatches = {
        check.check_id: (check.default_severity, DEFAULT_CONFIG[check.check_id]["severity"])
        for check in create_default_registry().get_all_checks()
        if "severity" in DEFAULT_CONFIG.get(check.check_id, {})
        and DEFAULT_CONFIG[check.check_id]["severity"] != check.default_severity
    }
    assert not mismatches


def test_every_default_severity_is_a_documented_level():
    for check in create_default_registry().get_all_checks():
        assert check.default_severity in VALID_SEVERITIES, check.check_id
    for check_id, entry in DEFAULT_CONFIG.items():
        if isinstance(entry, dict) and "severity" in entry:
            assert entry["severity"] in VALID_SEVERITIES, check_id
