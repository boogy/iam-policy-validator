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

    async def test_config_path_passed(self):
        with patch("iam_validator.sdk.context.AWSServiceFetcher") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_instance

            async with validator(config_path="/tmp/config.yaml") as ctx:
                assert ctx.config_path == "/tmp/config.yaml"

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

    async def test_passes_config_path(self):
        with patch("iam_validator.sdk.context.AWSServiceFetcher") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_instance

            async with validator_from_config("/path/to/config.yaml") as ctx:
                assert ctx.config_path == "/path/to/config.yaml"
