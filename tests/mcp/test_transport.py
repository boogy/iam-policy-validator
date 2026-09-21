"""Transport-layer integration tests using the in-process FastMCP Client.

Round-trips the MCP protocol against the actual server instance to catch:
- tool registration regressions
- annotation/tag drift
- response-shape changes
- resource catalog drift
"""

from fastmcp.client import Client

from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings

mcp = build_server(ServerSettings())


async def test_validate_policies_round_trip():
    async with Client(mcp) as client:
        result = await client.call_tool(
            "validate_policies",
            {
                "policies": [
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::b/*",
                            }
                        ],
                    }
                ]
            },
        )
        assert result.is_error is False
        assert result.structured_content is not None
        assert "issues" in result.structured_content["results"][0]


async def test_resources_listed():
    async with Client(mcp) as client:
        resources = await client.list_resources()
        uris = {str(r.uri) for r in resources}
        assert "iam://checks" in uris
        assert "iam://config-schema" in uris


async def test_resource_templates_listed():
    """Parameterized resources (Task 6g) must register as resource templates."""
    async with Client(mcp) as client:
        templates = await client.list_resource_templates()
        uris = {str(t.uriTemplate) for t in templates}
        assert "iam://sensitive-actions/{category}" in uris
        assert "iam://checks/{check_id}" in uris


async def test_check_details_resource_round_trip():
    """Fetching iam://checks/{check_id} returns registry-driven JSON for a real check."""
    import json

    async with Client(mcp) as client:
        result = await client.read_resource("iam://checks/wildcard_action")
        assert result, "expected non-empty content"
        # FastMCP returns a list of TextResourceContents; first contains JSON.
        text = result[0].text if hasattr(result[0], "text") else str(result[0])
        payload = json.loads(text)
        assert payload["check_id"] == "wildcard_action"
        assert payload["description"]
        assert payload["default_severity"] is not None


async def test_sensitive_actions_resource_round_trip():
    """Fetching iam://sensitive-actions/{category} returns the category's actions."""
    import json

    async with Client(mcp) as client:
        result = await client.read_resource("iam://sensitive-actions/credential_exposure")
        text = result[0].text if hasattr(result[0], "text") else str(result[0])
        payload = json.loads(text)
        assert payload["category"] == "credential_exposure"
        assert isinstance(payload["actions"], list)
        assert len(payload["actions"]) > 0


async def test_unknown_check_id_resource_returns_not_found_shape():
    """iam://checks/{unknown} returns the registry's 'Check not found' shape."""
    import json

    async with Client(mcp) as client:
        result = await client.read_resource("iam://checks/nonexistent_xyz")
        text = result[0].text if hasattr(result[0], "text") else str(result[0])
        payload = json.loads(text)
        assert payload["description"] == "Check not found"


async def test_tool_annotations_round_trip():
    """Verify ToolAnnotations survive the protocol."""
    async with Client(mcp) as client:
        tools = await client.list_tools()
        by_name = {t.name: t for t in tools}
        assert by_name["validate_policies"].annotations.readOnlyHint is True
        assert by_name["set_organization_config"].annotations.destructiveHint is False
        assert by_name["aws_access_analyzer_validate"].annotations.openWorldHint is True


async def test_demoted_resources_no_longer_registered_as_tools():
    """list_checks/list_sensitive_actions/get_check_details = resources, not tools."""
    async with Client(mcp) as client:
        names = {t.name for t in await client.list_tools()}
        assert "list_checks" not in names
        assert "list_sensitive_actions" not in names
        assert "get_check_details" not in names
