import re

from iam_validator.core.formatters.html import HTMLFormatter


def test_first_statement_is_not_rendered_as_global(report):
    details = HTMLFormatter()._render_policy_details(report)
    headings = re.findall(r"<h4>(.*?)</h4>", details)

    assert headings == ["Policy-level", "Statement 1"]
