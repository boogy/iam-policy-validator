import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _python_version_file() -> str:
    return (ROOT / ".python-version").read_text().strip()


def test_python_version_file_is_major_minor() -> None:
    assert re.fullmatch(r"3\.\d+", _python_version_file())


def test_dockerfile_python_version_matches_python_version_file() -> None:
    match = re.search(r"^ARG PYTHON_VERSION=(\S+)$", (ROOT / "Dockerfile").read_text(), re.M)
    assert match, "Dockerfile must declare a global `ARG PYTHON_VERSION=<version>`"
    assert match.group(1) == _python_version_file()


def test_dockerfile_has_no_hardcoded_python_version() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    body = re.sub(r"^ARG PYTHON_VERSION=\S+$", "", dockerfile, flags=re.M)
    assert not re.findall(r"python:?3\.\d+", body)
