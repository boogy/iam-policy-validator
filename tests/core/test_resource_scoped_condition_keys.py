"""Condition keys scoped to one resource type, checked against the statement's resources."""

import pytest

from iam_validator.core.aws_service.validators import ServiceValidator
from iam_validator.core.models import ActionDetail, ConditionKey, ResourceType, ServiceDetail

OBJECT_ARN = "arn:aws:s3:::bucket/key"
ACCESS_POINT_OBJECT_ARN = "arn:aws:s3:us-east-1:123456789012:accesspoint/ap/object/key"


@pytest.fixture
def s3_service() -> ServiceDetail:
    return ServiceDetail(
        Name="s3",
        prefix="s3",
        Actions=[
            ActionDetail(
                Name="GetObject",
                ActionConditionKeys=["s3:ExistingObjectTag/${TagKey}"],
                Resources=[{"Name": "object"}, {"Name": "accesspointobject"}],
            )
        ],
        Resources=[
            ResourceType(Name="object", ARNFormats=["arn:${Partition}:s3:::${BucketName}/${ObjectName}"]),
            ResourceType(
                Name="accesspointobject",
                ARNFormats=[
                    "arn:${Partition}:s3:${Region}:${Account}:accesspoint/${AccessPointName}/object/${ObjectName}"
                ],
                ConditionKeys=["s3:DataAccessPointAccount"],
            ),
        ],
        ConditionKeys=[
            ConditionKey(Name="s3:DataAccessPointAccount"),
            ConditionKey(Name="s3:ExistingObjectTag/${TagKey}"),
        ],
    )


async def _validate(service: ServiceDetail, condition_key: str, resources: list[str] | None):
    return await ServiceValidator().validate_condition_key("s3:GetObject", condition_key, service, resources)


@pytest.mark.parametrize("action", ["s3:GetObject", "s3:Get*"])
async def test_key_scoped_to_other_resource_type_is_invalid(s3_service, action):
    result = await ServiceValidator().validate_condition_key(
        action, "s3:DataAccessPointAccount", s3_service, [OBJECT_ARN]
    )

    assert not result.is_valid
    assert "accesspointobject" in (result.error_message or "")


@pytest.mark.parametrize(
    "resources",
    [
        None,
        [],
        ["*"],
        [ACCESS_POINT_OBJECT_ARN],
        [OBJECT_ARN, ACCESS_POINT_OBJECT_ARN],
        ["arn:aws:s3:::bucket/${aws:username}/*"],
        ["arn:aws:ec2:us-east-1:123456789012:instance/i-1"],
    ],
)
async def test_key_scoped_to_resource_type_is_valid_when_a_resource_may_match(s3_service, resources):
    assert (await _validate(s3_service, "s3:DataAccessPointAccount", resources)).is_valid


async def test_action_level_key_ignores_resource_types(s3_service):
    assert (await _validate(s3_service, "s3:ExistingObjectTag/env", [OBJECT_ARN])).is_valid
