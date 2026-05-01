import pytest
from unittest.mock import MagicMock
from iam_validator.core.pr_commenter import PRCommenter
from iam_validator.core.constants import SUMMARY_IDENTIFIER, REVIEW_IDENTIFIER

@pytest.mark.asyncio
async def test_pr_commenter_with_comment_id():
    """Test that PRCommenter correctly appends comment_id to identifiers."""
    github = MagicMock()
    
    # Test with no comment_id
    commenter_default = PRCommenter(github=github)
    assert commenter_default.SUMMARY_IDENTIFIER == SUMMARY_IDENTIFIER
    assert commenter_default.REVIEW_IDENTIFIER == REVIEW_IDENTIFIER
    
    # Test with custom comment_id
    comment_id = "policy-scan"
    commenter_custom = PRCommenter(github=github, comment_id=comment_id)
    
    expected_summary = SUMMARY_IDENTIFIER.replace(" -->", f"-{comment_id} -->")
    expected_review = REVIEW_IDENTIFIER.replace(" -->", f"-{comment_id} -->")
    
    assert commenter_custom.SUMMARY_IDENTIFIER == expected_summary
    assert commenter_custom.REVIEW_IDENTIFIER == expected_review
    assert f"-{comment_id}" in commenter_custom.SUMMARY_IDENTIFIER

@pytest.mark.asyncio
async def test_pr_commenter_different_ids_dont_clash():
    """Test that different comment_ids result in different markers."""
    github = MagicMock()
    
    commenter_policy = PRCommenter(github=github, comment_id="policy")
    commenter_role = PRCommenter(github=github, comment_id="role")
    
    assert commenter_policy.SUMMARY_IDENTIFIER != commenter_role.SUMMARY_IDENTIFIER
    assert "policy" in commenter_policy.SUMMARY_IDENTIFIER
    assert "role" in commenter_role.SUMMARY_IDENTIFIER
