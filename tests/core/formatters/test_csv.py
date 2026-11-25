import csv
import io

from iam_validator.core.formatters.csv import CSVFormatter


def _statement_cells(output: str) -> dict[str, str]:
    rows = list(csv.reader(io.StringIO(output)))
    header = next(r for r in rows if "Message" in r)
    return {row[header.index("Message")]: row[1] for row in rows[rows.index(header) + 1 :]}


def test_policy_level_issue_has_empty_statement_cell(report):
    cells = _statement_cells(CSVFormatter().format(report, include_summary=False))

    assert cells == {"policy-level-msg": "", "first-statement-msg": "1"}
