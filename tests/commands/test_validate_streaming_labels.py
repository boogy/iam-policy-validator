"""Tests for label management in streaming-mode validation.

Verifies two invariants:

1. Per-file review posting must NOT manage labels — each mini-report sees only
   one file's severities, so letting it manage labels would cause earlier files'
   labels to be removed the moment a label-free file is processed.
2. The final-cleanup pass must manage labels against the *aggregated* report,
   so the PR label set reflects the full validation outcome.
"""

from argparse import Namespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from iam_validator.commands.validate import ValidateCommand
from iam_validator.core.models import PolicyValidationResult, ValidationIssue


@pytest.fixture
def sample_result():
    return PolicyValidationResult(
        policy_file="policy.json",
        is_valid=False,
        issues=[
            ValidationIssue(
                severity="critical",
                statement_index=0,
                issue_type="full_wildcard",
                message="Full wildcard",
            ),
        ],
    )


@pytest.fixture
def streaming_args():
    return Namespace(
        config=None,
        no_owner_ignore=False,
        off_diff_comment_mode=None,
        github_review=True,
        github_comment=False,
    )


@pytest.mark.asyncio
async def test_post_file_review_disables_label_management(sample_result, streaming_args):
    """_post_file_review must pass manage_labels=False."""
    command = ValidateCommand()

    mock_commenter = MagicMock()
    mock_commenter.post_findings_to_pr = AsyncMock(return_value=True)

    mock_github = MagicMock()
    mock_github.is_configured = MagicMock(return_value=True)
    mock_github_cm = MagicMock()
    mock_github_cm.__aenter__ = AsyncMock(return_value=mock_github)
    mock_github_cm.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("iam_validator.commands.validate.GitHubIntegration", return_value=mock_github_cm),
        patch("iam_validator.core.pr_commenter.PRCommenter", return_value=mock_commenter),
    ):
        await command._post_file_review(sample_result, streaming_args)

    mock_commenter.post_findings_to_pr.assert_awaited_once()
    kwargs = mock_commenter.post_findings_to_pr.await_args.kwargs
    assert kwargs.get("manage_labels") is False, (
        "Per-file streaming review must not manage labels — labels are owned by the final cleanup pass."
    )


@pytest.mark.asyncio
async def test_final_cleanup_enables_label_management_when_configured(sample_result, streaming_args):
    """_run_final_review_cleanup must manage labels when severity_labels is configured."""
    command = ValidateCommand()

    mock_commenter = MagicMock()
    mock_commenter.post_findings_to_pr = AsyncMock(return_value=True)

    mock_github = MagicMock()
    mock_github.is_configured = MagicMock(return_value=True)
    mock_github_cm = MagicMock()
    mock_github_cm.__aenter__ = AsyncMock(return_value=mock_github)
    mock_github_cm.__aexit__ = AsyncMock(return_value=None)

    mock_config = MagicMock()
    mock_config.get_setting = MagicMock(
        side_effect=lambda key, default=None: {
            "fail_on_severity": ["error", "critical"],
            "severity_labels": {"critical": "security-critical"},
            "ignore_settings": {},
        }.get(key, default)
    )

    with (
        patch("iam_validator.commands.validate.GitHubIntegration", return_value=mock_github_cm),
        patch("iam_validator.core.pr_commenter.PRCommenter", return_value=mock_commenter),
        patch("iam_validator.core.config.config_loader.ConfigLoader.load_config", return_value=mock_config),
    ):
        await command._run_final_review_cleanup(streaming_args, [sample_result], {"policy.json"})

    mock_commenter.post_findings_to_pr.assert_awaited_once()
    kwargs = mock_commenter.post_findings_to_pr.await_args.kwargs
    assert kwargs.get("manage_labels") is True, (
        "Final cleanup must manage labels when severity_labels is configured."
    )


@pytest.mark.asyncio
async def test_final_cleanup_skips_label_management_when_not_configured(sample_result, streaming_args):
    """_run_final_review_cleanup must NOT manage labels when severity_labels is empty."""
    command = ValidateCommand()

    mock_commenter = MagicMock()
    mock_commenter.post_findings_to_pr = AsyncMock(return_value=True)

    mock_github = MagicMock()
    mock_github.is_configured = MagicMock(return_value=True)
    mock_github_cm = MagicMock()
    mock_github_cm.__aenter__ = AsyncMock(return_value=mock_github)
    mock_github_cm.__aexit__ = AsyncMock(return_value=None)

    mock_config = MagicMock()
    mock_config.get_setting = MagicMock(
        side_effect=lambda key, default=None: {
            "fail_on_severity": ["error", "critical"],
            "severity_labels": {},
            "ignore_settings": {},
        }.get(key, default)
    )

    with (
        patch("iam_validator.commands.validate.GitHubIntegration", return_value=mock_github_cm),
        patch("iam_validator.core.pr_commenter.PRCommenter", return_value=mock_commenter),
        patch("iam_validator.core.config.config_loader.ConfigLoader.load_config", return_value=mock_config),
    ):
        await command._run_final_review_cleanup(streaming_args, [sample_result], {"policy.json"})

    mock_commenter.post_findings_to_pr.assert_awaited_once()
    kwargs = mock_commenter.post_findings_to_pr.await_args.kwargs
    assert kwargs.get("manage_labels") is False, (
        "Final cleanup must skip label management when no severity_labels are configured."
    )
