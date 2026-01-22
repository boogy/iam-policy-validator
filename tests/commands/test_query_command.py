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
                ARNFormats=[
                    "arn:${Partition}:test:${Region}:${Account}:table/${TableName}/index/${IndexName}"
                ],
                ConditionKeys=["test:IndexArn"],
            ),
        ],
        ConditionKeys=[
            ConditionKey(Name="test:condition1", Description="Test condition 1", Types=["String"]),
            ConditionKey(
                Name="test:condition2", Description="Test condition 2", Types=["String", "ARN"]
            ),
        ],
    )


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

    def test_get_access_level_read(self, query_cmd: QueryCommand) -> None:
        """Test access level detection for read actions."""
        action = ActionDetail(
            Name="GetItem",
            Annotations={
                "Properties": {
                    "IsList": False,
                    "IsPermissionManagement": False,
                    "IsTaggingOnly": False,
                    "IsWrite": False,
                }
            },
        )
        assert query_cmd._get_access_level(action) == "read"

    def test_get_access_level_write(self, query_cmd: QueryCommand) -> None:
        """Test access level detection for write actions."""
        action = ActionDetail(
            Name="PutItem",
            Annotations={
                "Properties": {
                    "IsList": False,
                    "IsPermissionManagement": False,
                    "IsTaggingOnly": False,
                    "IsWrite": True,
                }
            },
        )
        assert query_cmd._get_access_level(action) == "write"

    def test_get_access_level_list(self, query_cmd: QueryCommand) -> None:
        """Test access level detection for list actions."""
        action = ActionDetail(
            Name="ListBuckets",
            Annotations={"Properties": {"IsList": True, "IsWrite": False}},
        )
        assert query_cmd._get_access_level(action) == "list"

    def test_get_access_level_permissions_management(self, query_cmd: QueryCommand) -> None:
        """Test access level detection for permissions management actions."""
        action = ActionDetail(
            Name="AttachPolicy",
            Annotations={"Properties": {"IsPermissionManagement": True}},
        )
        assert query_cmd._get_access_level(action) == "permissions-management"

    def test_get_access_level_tagging(self, query_cmd: QueryCommand) -> None:
        """Test access level detection for tagging actions."""
        action = ActionDetail(
            Name="TagResource",
            Annotations={
                "Properties": {
                    "IsTaggingOnly": True,
                    "IsWrite": True,  # Write flag also set, but tagging takes priority
                }
            },
        )
        assert query_cmd._get_access_level(action) == "tagging"

    def test_get_access_level_no_annotations(self, query_cmd: QueryCommand) -> None:
        """Test access level detection with no annotations."""
        action = ActionDetail(Name="SomeAction")
        assert query_cmd._get_access_level(action) == "Unknown"

    @pytest.mark.asyncio
    async def test_query_action_table_all_actions(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test querying all actions for a service."""
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
                output="json",
            )

            result = await query_cmd.execute(args)
            assert result == 0

    @pytest.mark.asyncio
    async def test_query_action_table_specific_action(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test querying specific action details."""
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
                output="json",
            )

            # Capture stdout
            with patch("builtins.print") as mock_print:
                result = await query_cmd.execute(args)
                assert result == 0

                # Verify the printed output
                printed_output = mock_print.call_args[0][0]
                result_dict = json.loads(printed_output)
                assert result_dict["action"] == "GetItem"
                assert result_dict["access_level"] == "read"
                assert "table" in result_dict["resource_types"]
                assert "test:condition1" in result_dict["condition_keys"]

    @pytest.mark.asyncio
    async def test_query_action_table_filter_by_access_level(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test filtering actions by access level."""
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
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
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
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
    async def test_query_arn_table_all(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test querying all ARN formats."""
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                assert result_dict["description"] == "Test condition 1"
                assert "String" in result_dict["types"]

    @pytest.mark.asyncio
    async def test_query_invalid_service(self, query_cmd: QueryCommand) -> None:
        """Test querying non-existent service."""
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(
                side_effect=ValueError("Service not found")
            )
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            args = argparse.Namespace(
                query_type="action",
                service="invalid",
                name=None,
                access_level=None,
                resource_type=None,
                condition=None,
                output="json",
            )

            result = await query_cmd.execute(args)
            assert result == 1
    @pytest.mark.asyncio
    async def test_query_action_text_format(
        self, query_cmd: QueryCommand, mock_service_detail: ServiceDetail
    ) -> None:
        """Test text format output for actions."""
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
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
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
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
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
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
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
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
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
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
                condition=None,
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
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            # expand_wildcard_action returns the same action as the exact query
            mock_fetcher.expand_wildcard_action = AsyncMock(
                return_value=["test:GetItem", "test:GetBucketInfo"]
            )
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Query both "GetItem" exactly and "Get*" wildcard, which should overlap
            args = argparse.Namespace(
                query_type="action",
                service=None,
                name=["test:GetItem", "test:Get*"],  # GetItem will be in both
                access_level=None,
                resource_type=None,
                condition=None,
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
        with patch(
            "iam_validator.commands.query.AWSServiceFetcher"
        ) as mock_fetcher_class:
            mock_fetcher = AsyncMock()
            mock_fetcher.fetch_service_by_name = AsyncMock(return_value=mock_service_detail)
            mock_fetcher.expand_wildcard_action = AsyncMock(
                return_value=["test:GetItem", "test:GetBucketInfo"]
            )
            mock_fetcher_class.return_value.__aenter__ = AsyncMock(return_value=mock_fetcher)
            mock_fetcher_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Query same wildcard pattern twice
            args = argparse.Namespace(
                query_type="action",
                service=None,
                name=["test:Get*", "test:Get*"],  # Identical patterns
                access_level=None,
                resource_type=None,
                condition=None,
                output="json",
                show_condition_keys=False,
                show_resource_types=False,
                show_access_level=False,
            )

            result = await query_cmd.execute(args)
            assert result == 0
