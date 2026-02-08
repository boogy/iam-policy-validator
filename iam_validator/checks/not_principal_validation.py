"""NotPrincipal validation check - detects dangerous NotPrincipal patterns in IAM policies.

NotPrincipal is a powerful IAM element that specifies principals that are NOT
granted or denied access. This check detects patterns that can lead to
unintended access:

1. NotPrincipal + Allow = AWS does not support this combination
2. NotPrincipal in any policy = AWS recommends conditions instead
"""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class NotPrincipalValidationCheck(PolicyCheck):
    """Checks for dangerous NotPrincipal usage patterns.

    Patterns detected:
    1. NotPrincipal with Effect: Allow - AWS does not support this combination.
       IAM will reject the policy or it will not work as expected.
    2. NotPrincipal in any policy - AWS recommends using Principal with
       condition operators (ArnNotEquals, StringNotEquals) as a safer alternative.
    """

    check_id: ClassVar[str] = "not_principal_validation"
    description: ClassVar[str] = "Checks for dangerous NotPrincipal usage patterns"
    default_severity: ClassVar[str] = "warning"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute NotPrincipal check on a statement."""
        del fetcher  # Unused

        issues = []

        # Only check statements that have NotPrincipal
        if statement.not_principal is None:
            return issues

        # Check 1: NotPrincipal with Effect: Allow is not supported by AWS
        if statement.effect == "Allow":
            issues.append(
                ValidationIssue(
                    severity="error",
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="not_principal_with_allow",
                    message=(
                        "`NotPrincipal` with `Effect: Allow` is not supported by AWS. "
                        "AWS IAM does not allow the `NotPrincipal` element in combination "
                        "with `Effect: Allow`. This policy will be rejected or will not "
                        "behave as expected."
                    ),
                    suggestion=(
                        'Use `Principal: "*"` with a `Condition` element using '
                        "`StringNotEquals` or `ArnNotEquals` to exclude specific principals."
                    ),
                    example=(
                        "{\n"
                        '  "Effect": "Allow",\n'
                        '  "Principal": "*",\n'
                        '  "Action": "s3:GetObject",\n'
                        '  "Resource": "arn:aws:s3:::my-bucket/*",\n'
                        '  "Condition": {\n'
                        '    "ArnNotEquals": {\n'
                        '      "aws:PrincipalArn": "arn:aws:iam::123456789012:root"\n'
                        "    }\n"
                        "  }\n"
                        "}"
                    ),
                    line_number=statement.line_number,
                    field_name="principal",
                )
            )
        else:
            # Check 2: NotPrincipal in Deny - valid but risky, recommend conditions instead
            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="not_principal_usage",
                    message=(
                        "`NotPrincipal` element detected. AWS recommends using "
                        "`Principal` with condition operators (`ArnNotEquals`, "
                        "`StringNotEquals`) instead of `NotPrincipal` for more "
                        "predictable behavior."
                    ),
                    suggestion=(
                        'Replace `NotPrincipal` with `Principal: "*"` and a `Condition` '
                        "element using `ArnNotEquals` or `StringNotEquals` to exclude "
                        "specific principals. This approach is more explicit and easier "
                        "to audit."
                    ),
                    example=(
                        "{\n"
                        '  "Effect": "Deny",\n'
                        '  "Principal": "*",\n'
                        '  "Action": "s3:*",\n'
                        '  "Resource": "arn:aws:s3:::my-bucket/*",\n'
                        '  "Condition": {\n'
                        '    "ArnNotEquals": {\n'
                        '      "aws:PrincipalArn": [\n'
                        '        "arn:aws:iam::123456789012:role/AdminRole",\n'
                        '        "arn:aws:iam::123456789012:root"\n'
                        "      ]\n"
                        "    }\n"
                        "  }\n"
                        "}"
                    ),
                    line_number=statement.line_number,
                    field_name="principal",
                )
            )

        return issues
