"""Tests for SDK context managers."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from iam_validator.core.models import PolicyValidationResult, ValidationIssue
from iam_validator.sdk.context import ValidationContext, validator, validator_from_config

# ---------------------------------------------------------------------------
# ValidationContext — direct instantiation
# ---------------------------------------------------------------------------


class TestValidationContext:
    """Tests for the ValidationContext class."""

    @pytest.fixture
    def ctx(self, mock_fetcher):
        return ValidationContext(mock_fetcher, config_path=None)

    async def test_validate_file(self, ctx, tmp_policy_file):
        with patch(
            "iam_validator.sdk.context.validate_policies",
            new_callable=AsyncMock,
            return_value=[
                PolicyValidationResult(
                    policy_file=str(tmp_policy_file),
                    is_valid=True,
                    issues=[],
                )
            ],
        ):
            result = await ctx.validate_file(tmp_policy_file)
            assert isinstance(result, PolicyValidationResult)
            assert result.is_valid is True

    async def test_validate_file_no_policies_raises(self, ctx, tmp_path):
        # A text file is not a valid policy and won't be loaded
        non_policy_file = tmp_path / "readme.txt"
        non_policy_file.write_text("this is not a policy")
        with pytest.raises((ValueError, Exception)):
            await ctx.validate_file(non_policy_file)

    async def test_validate_directory(self, ctx, tmp_policy_dir):
        with patch(
            "iam_validator.sdk.context.validate_policies",
            new_callable=AsyncMock,
            return_value=[
                PolicyValidationResult(policy_file="p1.json", is_valid=True, issues=[]),
                PolicyValidationResult(policy_file="p2.json", is_valid=False, issues=[]),
            ],
        ):
            results = await ctx.validate_directory(tmp_policy_dir)
            assert isinstance(results, list)
            assert len(results) == 2

    async def test_validate_directory_no_policies_raises(self, ctx, tmp_path):
        # Empty directory
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(ValueError, match="No IAM policies found"):
            await ctx.validate_directory(empty_dir)

    async def test_validate_json(self, ctx, valid_policy_dict):
        with patch(
            "iam_validator.sdk.context.validate_policies",
            new_callable=AsyncMock,
            return_value=[
                PolicyValidationResult(
                    policy_file="inline-policy",
                    is_valid=True,
                    issues=[],
                )
            ],
        ):
            result = await ctx.validate_json(valid_policy_dict)
            assert result.is_valid is True
            assert result.policy_file == "inline-policy"

    async def test_validate_json_custom_name(self, ctx, valid_policy_dict):
        with patch(
            "iam_validator.sdk.context.validate_policies",
            new_callable=AsyncMock,
            return_value=[
                PolicyValidationResult(
                    policy_file="my-custom-name",
                    is_valid=True,
                    issues=[],
                )
            ],
        ):
            result = await ctx.validate_json(valid_policy_dict, policy_name="my-custom-name")
            assert result.policy_file == "my-custom-name"


class TestValidationContextReport:
    """Tests for ValidationContext.generate_report()."""

    @pytest.fixture
    def ctx(self, mock_fetcher):
        return ValidationContext(mock_fetcher)

    @pytest.fixture
    def sample_results(self):
        return [
            PolicyValidationResult(
                policy_file="test.json",
                is_valid=False,
                issues=[
                    ValidationIssue(
                        severity="medium",
                        statement_index=0,
                        issue_type="overly_permissive",
                        message="Wildcard action",
                    )
                ],
            )
        ]

    def test_generate_json_report(self, ctx, sample_results):
        result = ctx.generate_report(sample_results, format="json")
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_generate_markdown_report(self, ctx, sample_results):
        result = ctx.generate_report(sample_results, format="markdown")
        assert isinstance(result, str)

    def test_generate_csv_report(self, ctx, sample_results):
        result = ctx.generate_report(sample_results, format="csv")
        assert isinstance(result, str)

    def test_generate_html_report(self, ctx, sample_results):
        result = ctx.generate_report(sample_results, format="html")
        assert isinstance(result, str)
        assert "<" in result  # Contains HTML tags

    def test_generate_sarif_report(self, ctx, sample_results):
        result = ctx.generate_report(sample_results, format="sarif")
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "$schema" in parsed

    def test_unknown_format_raises(self, ctx, sample_results):
        with pytest.raises(ValueError, match="Unknown format"):
            ctx.generate_report(sample_results, format="xml")

    def test_console_format_returns_empty(self, ctx, sample_results):
        result = ctx.generate_report(sample_results, format="console")
        assert result == ""


# ---------------------------------------------------------------------------
# validator() context manager
# ---------------------------------------------------------------------------


class TestValidatorContextManager:
    """Tests for the validator() async context manager."""

    async def test_yields_validation_context(self):
        with patch("iam_validator.sdk.context.AWSServiceFetcher") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_instance

            async with validator() as ctx:
                assert isinstance(ctx, ValidationContext)
                assert ctx.fetcher is mock_instance

    async def test_config_path_passed(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("settings:\n  cache_enabled: false\n")
        with patch("iam_validator.sdk.context.AWSServiceFetcher") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_instance

            async with validator(config_path=str(config_file)) as ctx:
                assert ctx.config_path == str(config_file)
                assert ctx.config.get_setting("cache_enabled") is False
            # The fetcher honours the config's cache settings, as the CLI's does.
            assert mock_cls.call_args.kwargs["enable_cache"] is False

    async def test_aws_services_dir_reaches_the_fetcher(self, tmp_path):
        with patch("iam_validator.sdk.context.AWSServiceFetcher") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_instance

            async with validator(aws_services_dir=str(tmp_path)):
                pass
            assert mock_cls.call_args.kwargs["aws_services_dir"] == str(tmp_path)

    async def test_fetcher_lifecycle(self):
        with patch("iam_validator.sdk.context.AWSServiceFetcher") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_instance

            async with validator():
                pass

            # aenter and aexit should have been called
            mock_instance.__aenter__.assert_awaited_once()
            mock_instance.__aexit__.assert_awaited_once()


# ---------------------------------------------------------------------------
# validator_from_config() context manager
# ---------------------------------------------------------------------------


class TestValidatorFromConfig:
    """Tests for the validator_from_config() async context manager."""

    async def test_passes_config_path(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("settings:\n  fail_on_severity: critical\n")
        with patch("iam_validator.sdk.context.AWSServiceFetcher") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_instance

            async with validator_from_config(str(config_file)) as ctx:
                assert ctx.config_path == str(config_file)
                assert ctx.config.get_setting("fail_on_severity") == ["critical"]

    async def test_accepts_loaded_config(self):
        from iam_validator.core.config.config_loader import ValidatorConfig

        config = ValidatorConfig({"settings": {"fail_on_severity": ["error"]}})
        with patch("iam_validator.sdk.context.AWSServiceFetcher") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_instance

            async with validator_from_config(config) as ctx:
                assert ctx.config is config


# ---------------------------------------------------------------------------
# CLI parity
# ---------------------------------------------------------------------------


class TestContextParity:
    """The context validates the way the CLI does and reuses what it built."""

    async def test_validate_json_forwards_raw_dict_and_shared_resources(self, mock_fetcher, valid_policy_dict):
        ctx = ValidationContext(mock_fetcher)
        with patch(
            "iam_validator.sdk.context.validate_policies",
            new_callable=AsyncMock,
            return_value=[PolicyValidationResult(policy_file="inline-policy", is_valid=True)],
        ) as spy:
            await ctx.validate_json(valid_policy_dict)
            await ctx.validate_json(json.dumps(valid_policy_dict))

        for call in spy.await_args_list:
            [(name, _policy, raw)] = call.args[0]
            assert name == "inline-policy"
            assert raw == valid_policy_dict
            assert call.kwargs["fetcher"] is mock_fetcher
        # Registry built once and reused, not rebuilt per call.
        assert spy.await_args_list[0].kwargs["registry"] is spy.await_args_list[1].kwargs["registry"]

    async def test_unparseable_file_is_a_failed_result(self, mock_fetcher, tmp_path):
        (tmp_path / "good.json").write_text(json.dumps({"Version": "2012-10-17", "Statement": []}))
        (tmp_path / "broken.json").write_text("{")
        ctx = ValidationContext(mock_fetcher)
        with patch(
            "iam_validator.sdk.context.validate_policies",
            new_callable=AsyncMock,
            return_value=[PolicyValidationResult(policy_file=str(tmp_path / "good.json"), is_valid=True)],
        ):
            results = await ctx.validate_directory(tmp_path)

        broken = [r for r in results if r.policy_file.endswith("broken.json")]
        assert len(results) == 2
        assert broken and broken[0].is_valid is False
        assert broken[0].issues[0].issue_type == "policy_parse_error"

    def test_markdown_report_matches_cli(self, mock_fetcher):
        from iam_validator.core.report import ReportGenerator

        results = [PolicyValidationResult(policy_file="p.json", is_valid=True)]
        generator = ReportGenerator()
        expected = generator.generate_github_comment(generator.generate_report(results))
        assert ValidationContext(mock_fetcher).generate_report(results, format="markdown") == expected
