"""Tests for query command."""

import argparse
import json
from unittest.mock import AsyncMock, patch

import pytest

from iam_validator.commands.query import QueryCommand
from iam_validator.core.models import ActionDetail, ConditionKey, ResourceType, ServiceDetail


@pytest.fixture
def query_cmd() -> QueryCommand:
    """Create query command instance."""
    return QueryCommand()


@pytest.fixture
def mock_service_detail() -> ServiceDetail:
    """Create mock service detail for testing."""
    return ServiceDetail(
        Name="TestService",
        Actions=[
            ActionDetail(
                Name="GetItem",
                Annotations={
                    "Properties": {
                        "IsList": False,
                        "IsPermissionManagement": False,
                        "IsTaggingOnly": False,
                        "IsWrite": False,
                    }
                },
                Resources=[{"Name": "table"}, {"Name": "index"}],
                ActionConditionKeys=["test:condition1", "test:condition2"],
            ),
            ActionDetail(
                Name="PutItem",
                Annotations={
                    "Properties": {
                        "IsList": False,
                        "IsPermissionManagement": False,
                        "IsTaggingOnly": False,
                        "IsWrite": True,
                    }
                },
                Resources=[{"Name": "table"}],
                ActionConditionKeys=["test:condition1"],
            ),
            ActionDetail(
                Name="ListTables",
                Annotations={
                    "Properties": {
                        "IsList": True,
                        "IsPermissionManagement": False,
                        "IsTaggingOnly": False,
                        "IsWrite": False,
                    }
                },
                Resources=[],
                ActionConditionKeys=[],
            ),
            ActionDetail(
                Name="AttachPolicy",
                Annotations={
                    "Properties": {
                        "IsList": False,
                        "IsPermissionManagement": True,
                        "IsTaggingOnly": False,
                        "IsWrite": False,
                    }
                },
                Resources=[{"Name": "role"}],
                ActionConditionKeys=[],
            ),
        ],
        Resources=[
            ResourceType(
                Name="table",
                ARNFormats=["arn:${Partition}:test:${Region}:${Account}:table/${TableName}"],
                ConditionKeys=["test:TableArn"],
            ),
            ResourceType(
                Name="index",
                ARNFormats=["arn:${Partition}:test:${Region}:${Account}:table/${TableName}/index/${IndexName}"],
                ConditionKeys=["test:IndexArn"],
            ),
        ],
        ConditionKeys=[
            ConditionKey(Name="test:condition1", Description="Test condition 1", Types=["String"]),
            ConditionKey(Name="test:condition2", Description="Test condition 2", Types=["String", "ARN"]),
        ],
    )


class TestMatchesConditionKey:
    """Test suite for _matches_condition_key helper."""

    def test_exact_match(self) -> None:
        """Exact condition key matches."""
        assert QueryCommand._matches_condition_key(["s3:authType"], "s3:authType") is True

    def test_prefix_match_template(self) -> None:
        """Prefix matches template keys like s3:BucketTag/${TagKey}."""
        keys = ["s3:BucketTag/${TagKey}", "s3:authType"]
        assert QueryCommand._matches_condition_key(keys, "s3:BucketTag") is True

    def test_no_match(self) -> None:
        """Non-matching key returns False."""
        assert QueryCommand._matches_condition_key(["s3:authType"], "s3:prefix") is False

    def test_case_insensitive(self) -> None:
        """Matching is case-insensitive."""
        assert QueryCommand._matches_condition_key(["s3:AuthType"], "s3:authtype") is True

    def test_empty_keys(self) -> None:
        """Empty condition key list returns False."""
        assert QueryCommand._matches_condition_key([], "s3:authType") is False

    def test_prefix_no_false_positive(self) -> None:
        """Prefix match requires / separator — s3:Bucket should not match s3:BucketTag."""
        assert QueryCommand._matches_condition_key(["s3:BucketTagging"], "s3:Bucket") is False

    def test_prefix_with_slash(self) -> None:
        """Specifying the full path also works."""
        keys = ["aws:ResourceTag/${TagKey}"]
        assert QueryCommand._matches_condition_key(keys, "aws:ResourceTag/${TagKey}") is True
        assert QueryCommand._matches_condition_key(keys, "aws:ResourceTag") is True


class TestQueryCommand:
    """Test suite for QueryCommand."""

    def test_name(self, query_cmd: QueryCommand) -> None:
        """Test command name."""
        assert query_cmd.name == "query"

    def test_help(self, query_cmd: QueryCommand) -> None:
        """Test command help text."""
        assert "Query AWS service definitions" in query_cmd.help

    def test_add_arguments(self, query_cmd: QueryCommand) -> None:
        """Test argument parsing setup."""
        parser = argparse.ArgumentParser()
        query_cmd.add_arguments(parser)

        # Test action-table subcommand
        args = parser.parse_args(["action", "--service", "s3"])
        assert args.query_type == "action"
        assert args.service == "s3"

        # Test arn-table subcommand
        args = parser.parse_args(["arn", "--service", "iam", "--name", "role"])
        assert args.query_type == "arn"
        assert args.service == "iam"
        assert args.name == "role"

        # Test condition-table subcommand
        args = parser.parse_args(["condition", "--service", "ec2", "--output", "yaml"])
        assert args.query_type == "condition"
        assert args.service == "ec2"
        assert args.output == "yaml"

    @pytest.mark.asyncio
    async def test_query_action_table_all_actions(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test querying all actions for a service."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="json",
            )

            result = await query_cmd.execute(args)
            assert result == 0

    @pytest.mark.asyncio
    async def test_query_action_table_specific_action(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test querying specific action details."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name="GetItem",
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="json",
            )

            # Capture stdout
            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Verify the printed output
                printed_output = mock_print.call_args[0][0]
                result_dict = json.loads(printed_output)
                assert result_dict["action"] == "test:GetItem"
                assert "description" not in result_dict
                assert result_dict["access_level"] == "read"
                assert "table" in result_dict["resource_types"]
                assert "test:condition1" in result_dict["condition_keys"]

    @pytest.mark.asyncio
    async def test_query_action_table_filter_by_access_level(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test filtering actions by access level."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level="write",
                resource_type=None,
                has_condition_key=None,
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 1
                assert result_list[0]["action"] == "test:PutItem"
                assert result_list[0]["access_level"] == "write"

    @pytest.mark.asyncio
    async def test_query_action_table_filter_by_wildcard_resource(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test filtering actions that support wildcard resource."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type="*",
                has_condition_key=None,
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                # Should only return ListTables (no required resources)
                assert len(result_list) == 1
                assert result_list[0]["action"] == "test:ListTables"

    @pytest.mark.asyncio
    async def test_query_arn_table_all(self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail) -> None:
        """Test querying all ARN formats."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                list_arn_types=False,
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 2
                assert any("table" in arn for arn in result_list)

    @pytest.mark.asyncio
    async def test_query_condition_table_specific(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test querying specific condition key."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="condition",
                service="test",
                name="test:condition1",
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_dict = json.loads(printed_output)
                assert result_dict["condition_key"] == "test:condition1"
                assert "description" not in result_dict
                assert "String" in result_dict["types"]

    @pytest.mark.asyncio
    async def test_query_invalid_service(self, query_cmd: QueryCommand) -> None:
        """Test querying non-existent service."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(side_effect=ValueError("Service not found"))
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="invalid",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="json",
            )

            result = await query_cmd.execute(args)
            assert result == 1

    @pytest.mark.asyncio
    async def test_query_action_text_format(self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail) -> None:
        """Test text format output for actions."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level="write",
                resource_type=None,
                has_condition_key=None,
                output="text",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Verify text output was printed
                assert mock_print.called
                # Should print just the action name
                printed_text = mock_print.call_args[0][0]
                assert "test:PutItem" == printed_text

    @pytest.mark.asyncio
    async def test_query_action_text_format_specific(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test text format output for specific action."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name="GetItem",
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="text",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Verify text output includes action name and details
                assert mock_print.call_count >= 3  # At least 3 lines printed
                calls = [call[0][0] for call in mock_print.call_args_list]
                assert "GetItem" in calls[0]
                assert any("Resource types" in call for call in calls)

    @pytest.mark.asyncio
    async def test_query_action_with_show_condition_keys(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --show-condition-keys filter."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="json",
                show_condition_keys=True,
                show_resource_types=False,
                show_access_level=False,
            )

            result = await query_cmd.execute(args)
            assert result == 0

    @pytest.mark.asyncio
    async def test_query_action_with_show_resource_types(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --show-resource-types filter."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="json",
                show_condition_keys=False,
                show_resource_types=True,
                show_access_level=False,
            )

            result = await query_cmd.execute(args)
            assert result == 0

    @pytest.mark.asyncio
    async def test_query_action_filter_text_output(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test field filters with text output format."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="text",
                show_condition_keys=True,
                show_resource_types=False,
                show_access_level=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Verify output includes condition keys
                calls = [str(call) for call in mock_print.call_args_list]
                assert any("Condition keys" in call for call in calls)

    @pytest.mark.asyncio
    async def test_query_action_deduplication(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test that duplicate actions are deduplicated in results."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            # expand_wildcard_action returns the same action as the exact query
            mock_fetcher.expand_wildcard_action = AsyncMock(return_value=["test:GetItem", "test:GetBucketInfo"])
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Query both "GetItem" exactly and "Get*" wildcard, which should overlap
            args = argparse.Namespace(
                query_type="action",
                service=None,
                name=["test:GetItem", "test:Get*"],  # GetItem will be in both
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="json",
                show_condition_keys=False,
                show_resource_types=False,
                show_access_level=False,
            )

            result = await query_cmd.execute(args)
            assert result == 0

    @pytest.mark.asyncio
    async def test_query_action_deduplication_identical_wildcards(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test that identical wildcard patterns don't produce duplicates."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher.expand_wildcard_action = AsyncMock(return_value=["test:GetItem", "test:GetBucketInfo"])
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Query same wildcard pattern twice
            args = argparse.Namespace(
                query_type="action",
                service=None,
                name=["test:Get*", "test:Get*"],  # Identical patterns
                access_level=None,
                resource_type=None,
                has_condition_key=None,
                output="json",
                show_condition_keys=False,
                show_resource_types=False,
                show_access_level=False,
            )

            result = await query_cmd.execute(args)
            assert result == 0

    @pytest.mark.asyncio
    async def test_query_action_has_condition_key_list_all(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key filter when listing all actions for a service."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key="test:condition2",
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Only GetItem has test:condition2
                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 1
                assert result_list[0]["action"] == "test:GetItem"

    @pytest.mark.asyncio
    async def test_query_action_has_condition_key_with_wildcard(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key filter with wildcard action patterns."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher.expand_wildcard_action = AsyncMock(return_value=["test:GetItem", "test:PutItem"])
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service=None,
                name=["test:*Item"],
                access_level=None,
                resource_type=None,
                has_condition_key="test:condition2",
                output="json",
                show_condition_keys=False,
                show_resource_types=False,
                show_access_level=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Only GetItem has test:condition2, PutItem does not
                printed_output = mock_print.call_args[0][0]
                result_dict = json.loads(printed_output)
                # Single result returns dict, not list
                assert result_dict["action"] == "test:GetItem"
                assert "test:condition2" in result_dict["condition_keys"]

    @pytest.mark.asyncio
    async def test_query_action_has_condition_key_no_match(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key filter returns empty when no actions match."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key="nonexistent:key",
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert result_list == []

    @pytest.mark.asyncio
    async def test_query_arn_has_condition_key(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key filter on ARN queries."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                has_condition_key="test:TableArn",
                list_arn_types=False,
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Only "table" resource type has test:TableArn
                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 1
                assert "table" in result_list[0]

    @pytest.mark.asyncio
    async def test_query_arn_has_condition_key_list_types(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key filter with --list-arn-types."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                has_condition_key="test:IndexArn",
                list_arn_types=True,
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 1
                assert result_list[0]["resource_type"] == "index"

    @pytest.mark.asyncio
    async def test_query_arn_has_condition_key_specific_name(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key filter on specific ARN type returns empty on mismatch."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Query specific ARN type "table" with a condition key it doesn't have
            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name="table",
                has_condition_key="test:IndexArn",
                list_arn_types=False,
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert result_list == []

    @pytest.mark.asyncio
    async def test_query_action_has_condition_key_prefix_match(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key uses prefix matching for template keys."""
        # Add an action with a template condition key like s3:BucketTag/${TagKey}
        mock_service_detail.actions["TagResource"] = ActionDetail(
            Name="TagResource",
            Annotations={"Properties": {"IsTaggingOnly": True}},
            Resources=[{"Name": "table"}],
            ActionConditionKeys=["test:Tag/${TagKey}", "test:condition1"],
        )

        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Filter with prefix "test:Tag" should match "test:Tag/${TagKey}"
            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key="test:Tag",
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                # _query_all_actions_for_service always returns a list
                assert len(result_list) == 1
                assert result_list[0]["action"] == "test:TagResource"

    @pytest.mark.asyncio
    async def test_query_action_has_condition_key_with_show_fields(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key works together with --show-resource-types."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher.expand_wildcard_action = AsyncMock(return_value=["test:GetItem", "test:PutItem"])
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service=None,
                name=["test:*Item"],
                access_level=None,
                resource_type=None,
                has_condition_key="test:condition2",
                output="json",
                show_condition_keys=False,
                show_resource_types=True,
                show_access_level=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Only GetItem has test:condition2
                printed_output = mock_print.call_args[0][0]
                result_dict = json.loads(printed_output)
                assert result_dict["action"] == "test:GetItem"
                assert "resource_types" in result_dict
                assert "table" in result_dict["resource_types"]

    @pytest.mark.asyncio
    async def test_query_action_has_condition_key_text_output(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key with text output produces simple action names."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="test",
                name=None,
                access_level=None,
                resource_type=None,
                has_condition_key="test:condition1",
                output="text",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # text output should print simple action names
                calls = [call[0][0] for call in mock_print.call_args_list]
                assert "test:GetItem" in calls
                assert "test:PutItem" in calls

    @pytest.mark.asyncio
    async def test_query_arn_has_condition_key_prefix_match(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --has-condition-key prefix matching on ARN queries."""
        # Add a resource type with template condition key
        mock_service_detail.resources["tagged"] = ResourceType(
            Name="tagged",
            ARNFormats=["arn:${Partition}:test:${Region}:${Account}:tagged/${Id}"],
            ConditionKeys=["test:ResourceTag/${TagKey}"],
        )

        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Prefix "test:ResourceTag" should match "test:ResourceTag/${TagKey}"
            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                has_condition_key="test:ResourceTag",
                list_arn_types=True,
                output="json",
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 1
                assert result_list[0]["resource_type"] == "tagged"

    @pytest.mark.asyncio
    async def test_query_action_condition_alias(self, query_cmd: QueryCommand) -> None:
        """Test that --condition works as an alias for --has-condition-key."""
        parser = argparse.ArgumentParser()
        query_cmd.add_arguments(parser)

        args = parser.parse_args(["action", "--service", "s3", "--condition", "s3:ResourceAccount"])
        assert args.has_condition_key == "s3:ResourceAccount"

        args = parser.parse_args(["action", "--service", "s3", "--has-condition-key", "s3:ResourceAccount"])
        assert args.has_condition_key == "s3:ResourceAccount"

    @pytest.mark.asyncio
    async def test_query_arn_show_condition_keys(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --show-condition-keys filter on ARN queries."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                has_condition_key=None,
                list_arn_types=False,
                output="json",
                show_condition_keys=True,
                show_arn_format=False,
                show_resource_type=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 2
                # Each item should have resource_type and condition_keys only
                for item in result_list:
                    assert "resource_type" in item
                    assert "condition_keys" in item
                    assert "arn_formats" not in item

    @pytest.mark.asyncio
    async def test_query_arn_show_arn_format(self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail) -> None:
        """Test --show-arn-format filter on ARN queries."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                has_condition_key=None,
                list_arn_types=False,
                output="json",
                show_condition_keys=False,
                show_arn_format=True,
                show_resource_type=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 2
                for item in result_list:
                    assert "resource_type" in item
                    assert "arn_formats" in item
                    assert "condition_keys" not in item

    @pytest.mark.asyncio
    async def test_query_arn_show_multiple_fields(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test combining --show-condition-keys and --show-arn-format on ARN queries."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                has_condition_key=None,
                list_arn_types=False,
                output="json",
                show_condition_keys=True,
                show_arn_format=True,
                show_resource_type=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                assert len(result_list) == 2
                for item in result_list:
                    assert "resource_type" in item
                    assert "arn_formats" in item
                    assert "condition_keys" in item

    @pytest.mark.asyncio
    async def test_query_arn_show_fields_with_condition_key_filter(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --show-condition-keys combined with --has-condition-key on ARN queries."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                has_condition_key="test:TableArn",
                list_arn_types=False,
                output="json",
                show_condition_keys=True,
                show_arn_format=True,
                show_resource_type=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_list = json.loads(printed_output)
                # Only "table" resource type has test:TableArn
                assert len(result_list) == 1
                assert result_list[0]["resource_type"] == "table"
                assert "test:TableArn" in result_list[0]["condition_keys"]
                assert "arn_formats" in result_list[0]

    @pytest.mark.asyncio
    async def test_query_arn_show_fields_specific_name(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test --show-condition-keys on a specific ARN type."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name="table",
                has_condition_key=None,
                list_arn_types=False,
                output="json",
                show_condition_keys=True,
                show_arn_format=False,
                show_resource_type=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                printed_output = mock_print.call_args[0][0]
                result_dict = json.loads(printed_output)
                assert result_dict["resource_type"] == "table"
                assert "condition_keys" in result_dict
                assert "test:TableArn" in result_dict["condition_keys"]
                assert "arn_formats" not in result_dict

    @pytest.mark.asyncio
    async def test_query_arn_show_fields_text_output(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test ARN field filters with text output format."""
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="arn",
                service="test",
                name=None,
                has_condition_key=None,
                list_arn_types=False,
                output="text",
                show_condition_keys=True,
                show_arn_format=True,
                show_resource_type=False,
            )

            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                calls = [str(call) for call in mock_print.call_args_list]
                # Should print resource type names and their fields
                assert any("table" in call for call in calls)
                assert any("Condition keys" in call for call in calls)

    @pytest.mark.asyncio
    async def test_query_arn_parser_has_show_flags(self, query_cmd: QueryCommand) -> None:
        """Test that ARN parser accepts --show-condition-keys, --show-arn-format, --show-resource-type."""
        parser = argparse.ArgumentParser()
        query_cmd.add_arguments(parser)

        args = parser.parse_args(
            [
                "arn",
                "--service",
                "s3",
                "--show-condition-keys",
                "--show-arn-format",
                "--show-resource-type",
            ]
        )
        assert args.show_condition_keys is True
        assert args.show_arn_format is True
        assert args.show_resource_type is True


def _plane_service() -> ServiceDetail:
    return ServiceDetail(
        Name="test",
        ServiceName="Test Service",
        Actions=[
            ActionDetail(Name="ReadData", Annotations={"Properties": {"IsDataPlane": True}}),
            ActionDetail(Name="CreateThing", Annotations={"Properties": {"IsWrite": True, "IsDataPlane": False}}),
            ActionDetail(Name="Unclassified", Annotations={"Properties": {"IsWrite": True}}),
        ],
        ConditionKeys=[ConditionKey(Name="test:key", Types=["String"])],
    )


async def _run_query(query_cmd: QueryCommand, argv: list[str], fetcher: AsyncMock) -> tuple[int, list[str]]:
    parser = argparse.ArgumentParser()
    query_cmd.add_arguments(parser)
    args = parser.parse_args(argv)
    with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
        mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=fetcher)
        mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)
        with patch("builtins.print") as mock_print:
            rc = await query_cmd.execute(args)
    return rc, [str(call.args[0]) for call in mock_print.call_args_list]


@pytest.fixture
def plane_fetcher() -> AsyncMock:
    from iam_validator.core.config.aws_global_conditions import get_global_conditions

    fetcher = AsyncMock()
    fetcher.fetch_service_by_name = AsyncMock(return_value=_plane_service())
    fetcher.expand_wildcard_action = AsyncMock(return_value=["test:ReadData", "test:CreateThing", "test:Unclassified"])
    fetcher.get_global_conditions = AsyncMock(return_value=get_global_conditions())
    return fetcher


class TestDataPlaneFilters:
    @pytest.mark.parametrize(
        "flag,expected",
        [
            ("--data-plane", ["test:ReadData"]),
            ("--control-plane", ["test:CreateThing"]),
        ],
    )
    async def test_list_all_filters_by_plane(self, query_cmd, plane_fetcher, flag, expected) -> None:
        rc, out = await _run_query(query_cmd, ["action", "--service", "test", flag, "--output", "text"], plane_fetcher)
        assert rc == 0
        assert out == expected

    async def test_wildcard_query_filters_by_plane(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd, ["action", "--name", "test:*", "--control-plane", "--output", "json"], plane_fetcher
        )
        assert rc == 0
        assert json.loads(out[0])["action"] == "test:CreateThing"

    async def test_exact_query_filtered_out_by_plane(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(query_cmd, ["action", "--name", "test:Unclassified", "--data-plane"], plane_fetcher)
        assert rc == 0
        assert json.loads(out[0]) == []

    def test_plane_flags_are_mutually_exclusive(self, query_cmd) -> None:
        parser = argparse.ArgumentParser()
        query_cmd.add_arguments(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["action", "--service", "s3", "--data-plane", "--control-plane"])

    async def test_full_output_includes_service_name_and_data_plane(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(query_cmd, ["action", "--name", "test:ReadData"], plane_fetcher)
        assert rc == 0
        result = json.loads(out[0])
        assert result["service_name"] == "Test Service"
        assert result["data_plane"] is True

    async def test_show_data_plane_text_reports_unclassified(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd, ["action", "--service", "test", "--show-data-plane", "--output", "text"], plane_fetcher
        )
        assert rc == 0
        assert out == [
            "test:ReadData",
            "  Plane: data",
            "test:CreateThing",
            "  Plane: control",
            "test:Unclassified",
            "  Plane: unclassified",
        ]

    async def test_condition_and_arn_details_include_service_name(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(query_cmd, ["condition", "--name", "test:key"], plane_fetcher)
        assert rc == 0
        assert json.loads(out[0])["service_name"] == "Test Service"


class TestGlobalConditionQuery:
    async def test_lists_all_global_keys(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(query_cmd, ["global-condition"], plane_fetcher)
        assert rc == 0
        keys = {k["condition_key"] for k in json.loads(out[0])}
        assert {"aws:SourceIp", "aws:ResourceTag/${TagKey}", "ec2:RoleDelivery"} <= keys

    async def test_type_filter_is_case_insensitive(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(query_cmd, ["global-condition", "--type", "bool"], plane_fetcher)
        assert rc == 0
        result = json.loads(out[0])
        assert result
        assert all("Bool" in k["types"] for k in result)

    async def test_concrete_tag_key_resolves_to_template(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd, ["global-condition", "--name", "aws:PrincipalTag/team", "--output", "text"], plane_fetcher
        )
        assert rc == 0
        assert out[0] == "aws:PrincipalTag/${TagKey}"

    async def test_unknown_key_fails(self, query_cmd, plane_fetcher) -> None:
        rc, _ = await _run_query(query_cmd, ["global-condition", "--name", "aws:Nope"], plane_fetcher)
        assert rc == 1

    async def test_wildcard_name_lists_matching_keys(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd, ["global-condition", "--name", "aws:Re*", "--output", "text"], plane_fetcher
        )
        assert rc == 0
        names = [line for line in "\n".join(out).splitlines() if line and not line.startswith(" ")]
        assert "aws:ResourceTag/${TagKey}" in names
        assert all(n.startswith("aws:Re") for n in names)

    async def test_wildcard_name_without_matches_fails(self, query_cmd, plane_fetcher) -> None:
        rc, _ = await _run_query(query_cmd, ["global-condition", "--name", "aws:Zzz*"], plane_fetcher)
        assert rc == 1


class TestFiltersApplyToNamedQueries:
    async def test_access_level_filters_wildcard_query(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd, ["action", "--name", "test:*", "--access-level", "write", "--output", "text"], plane_fetcher
        )
        assert rc == 0
        assert out == ["test:CreateThing", "test:Unclassified"]

    async def test_access_level_filters_exact_query(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd, ["action", "--name", "test:CreateThing", "--access-level", "read"], plane_fetcher
        )
        assert rc == 0
        assert json.loads(out[0]) == []

    @pytest.mark.parametrize("resource_type,expected", [("*", {"test:ReadData"}), ("thing", {"test:CreateThing"})])
    async def test_resource_type_filters_wildcard_query(
        self, query_cmd, plane_fetcher, resource_type, expected
    ) -> None:
        service = _plane_service()
        service.actions["CreateThing"].resources = [{"Name": "thing"}]
        plane_fetcher.fetch_service_by_name = AsyncMock(return_value=service)
        plane_fetcher.expand_wildcard_action = AsyncMock(return_value=["test:ReadData", "test:CreateThing"])
        rc, out = await _run_query(
            query_cmd,
            ["action", "--name", "test:*", "--resource-type", resource_type, "--output", "text"],
            plane_fetcher,
        )
        assert rc == 0
        assert set(out) == expected


class TestShowFieldFilters:
    @pytest.fixture
    def api_fetcher(self, plane_fetcher) -> AsyncMock:
        from iam_validator.core.config.aws_global_conditions import AWSGlobalConditions

        plane_fetcher.get_global_conditions = AsyncMock(
            return_value=AWSGlobalConditions.from_api(
                [
                    {
                        "Name": "aws:EpochTime",
                        "Description": "Request time",
                        "DocPage": "/IAM/latest/UserGuide/reference_policies_condition-keys.html#epochtime",
                        "Types": ["Numeric", "Date"],
                    }
                ]
            )
        )
        return plane_fetcher

    async def test_show_service_name(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd, ["action", "--name", "test:ReadData", "--show-service-name", "--output", "text"], plane_fetcher
        )
        assert rc == 0
        assert out == ["test:ReadData", "  Service name: Test Service"]

    async def test_condition_show_types(self, query_cmd, plane_fetcher) -> None:
        rc, out = await _run_query(query_cmd, ["condition", "--service", "test", "--show-types"], plane_fetcher)
        assert rc == 0
        assert json.loads(out[0]) == [{"condition_key": "test:key", "types": ["String"]}]

    async def test_global_show_types_only(self, query_cmd, api_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd, ["global-condition", "--name", "aws:EpochTime", "--show-types"], api_fetcher
        )
        assert rc == 0
        assert json.loads(out[0]) == {"condition_key": "aws:EpochTime", "types": ["Numeric", "Date"]}

    async def test_global_show_description_and_doc_url_text(self, query_cmd, api_fetcher) -> None:
        rc, out = await _run_query(
            query_cmd,
            ["global-condition", "--show-description", "--show-doc-url", "--output", "text"],
            api_fetcher,
        )
        assert rc == 0
        assert out[out.index("aws:EpochTime") + 1] == "  Description: Request time"
        assert out[out.index("aws:EpochTime") + 2].startswith("  Documentation: https://docs.aws.amazon.com/")


class TestQueryExamples:
    async def test_all_topics_without_fetcher(self, query_cmd, capsys) -> None:
        from iam_validator.commands.query import QUERY_EXAMPLES

        parser = argparse.ArgumentParser()
        query_cmd.add_arguments(parser)
        with patch("iam_validator.commands.query.AWSServiceFetcher") as mock_fetcher_class:
            rc = await query_cmd.execute(parser.parse_args(["examples"]))
        assert rc == 0
        mock_fetcher_class.assert_not_called()
        out = capsys.readouterr().out
        assert all(f"\n{topic}\n" in f"\n{out}" for topic in QUERY_EXAMPLES)

    async def test_single_topic(self, query_cmd, capsys) -> None:
        parser = argparse.ArgumentParser()
        query_cmd.add_arguments(parser)
        assert await query_cmd.execute(parser.parse_args(["examples", "global-condition"])) == 0
        out = capsys.readouterr().out
        assert "query global-condition" in out
        assert "query arn" not in out

    def test_unknown_topic_rejected(self, query_cmd) -> None:
        parser = argparse.ArgumentParser()
        query_cmd.add_arguments(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["examples", "nope"])

    def test_query_help_points_to_examples(self, query_cmd) -> None:
        parser = argparse.ArgumentParser(epilog=query_cmd.epilog)
        query_cmd.add_arguments(parser)
        help_text = parser.format_help()
        assert "iam-validator query examples" in help_text
        assert "$ " not in help_text
