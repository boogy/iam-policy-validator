"""Third-party checks register through the `iam_validator.checks` entry-point group."""

from iam_validator.core.check_registry import CheckRegistry, PolicyCheck, load_entry_point_checks


class _FakeEntryPoint:
    name = "fake_plugin_check"

    def load(self):
        class FakePluginCheck(PolicyCheck):
            check_id = "fake_plugin_check"
            description = "registered via entry point"
            default_severity = "low"

            async def execute(self, statement, statement_idx, fetcher, config):
                return []

        return FakePluginCheck


def test_entry_point_checks_are_registered(monkeypatch):
    monkeypatch.setattr(
        "iam_validator.core.check_registry.entry_points",
        lambda group: [_FakeEntryPoint()],
    )
    registry = CheckRegistry()
    loaded = load_entry_point_checks(registry)

    assert loaded == ["fake_plugin_check"]
    assert registry.get_check("fake_plugin_check") is not None


def test_colliding_check_id_is_skipped_and_builtin_survives(monkeypatch, caplog):
    import logging

    from iam_validator.checks.wildcard_action import WildcardActionCheck

    class _CollidingEntryPoint:
        name = "colliding_plugin"

        def load(self):
            class CollidingCheck(PolicyCheck):
                check_id = "wildcard_action"
                description = "shadows the built-in wildcard_action check"
                default_severity = "low"

                async def execute(self, statement, statement_idx, fetcher, config):
                    return []

            return CollidingCheck

    monkeypatch.setattr(
        "iam_validator.core.check_registry.entry_points",
        lambda group: [_CollidingEntryPoint(), _FakeEntryPoint()],
    )
    registry = CheckRegistry()
    builtin = WildcardActionCheck()
    registry.register(builtin)

    with caplog.at_level(logging.WARNING):
        loaded = load_entry_point_checks(registry)

    assert loaded == ["fake_plugin_check"]
    assert registry.get_check("wildcard_action") is builtin
    assert any("colliding_plugin" in r.message and "wildcard_action" in r.message for r in caplog.records)


def test_a_broken_entry_point_does_not_abort_discovery(monkeypatch, caplog):
    import logging

    class _Broken:
        name = "broken"

        def load(self):
            raise ImportError("missing dependency")

    monkeypatch.setattr(
        "iam_validator.core.check_registry.entry_points",
        lambda group: [_Broken(), _FakeEntryPoint()],
    )
    registry = CheckRegistry()
    with caplog.at_level(logging.WARNING):
        loaded = load_entry_point_checks(registry)

    assert loaded == ["fake_plugin_check"]
    assert any("broken" in r.message for r in caplog.records)


def test_non_policy_check_entry_point_is_skipped(monkeypatch, caplog):
    import logging

    class _NotACheck:
        check_id = "impostor"

    class _NonCheckEntryPoint:
        name = "impostor_plugin"

        def load(self):
            return _NotACheck

    monkeypatch.setattr(
        "iam_validator.core.check_registry.entry_points",
        lambda group: [_NonCheckEntryPoint(), _FakeEntryPoint()],
    )
    registry = CheckRegistry()
    with caplog.at_level(logging.WARNING):
        loaded = load_entry_point_checks(registry)

    assert loaded == ["fake_plugin_check"]
    assert registry.get_check("impostor") is None
    assert any("impostor_plugin" in r.getMessage() and "_NotACheck" in r.getMessage() for r in caplog.records)


async def test_run_completes_when_a_non_check_plugin_is_advertised(monkeypatch):
    from iam_validator.core.models import IAMPolicy
    from iam_validator.core.policy_checks import validate_policies

    class _NotACheck:
        check_id = "impostor"

    class _NonCheckEntryPoint:
        name = "impostor_plugin"

        def load(self):
            return _NotACheck

    monkeypatch.setattr(
        "iam_validator.core.check_registry.entry_points",
        lambda group: [_NonCheckEntryPoint()],
    )
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    results = await validate_policies([("inline.json", IAMPolicy.model_validate(policy), policy)])

    assert len(results) == 1


def test_loaded_entry_point_check_ids_are_logged(monkeypatch, caplog):
    import logging

    from iam_validator.core.check_registry import create_default_registry

    monkeypatch.setattr(
        "iam_validator.core.check_registry.entry_points",
        lambda group: [_FakeEntryPoint()],
    )
    with caplog.at_level(logging.INFO, logger="iam_validator.core.check_registry"):
        registry = create_default_registry()

    assert registry.get_check("fake_plugin_check") is not None
    assert any("fake_plugin_check" in r.getMessage() for r in caplog.records)
