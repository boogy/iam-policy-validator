"""Tests for SDK exception hierarchy."""

import pytest

from iam_validator.sdk.exceptions import (
    AWSServiceError,
    ConfigurationError,
    IAMValidatorError,
    InvalidPolicyFormatError,
    PolicyLoadError,
    PolicyValidationError,
    UnsupportedPolicyTypeError,
)


class TestExceptionHierarchy:
    """Verify the exception class hierarchy and catchability."""

    def test_base_exception_is_exception(self):
        assert issubclass(IAMValidatorError, Exception)

    @pytest.mark.parametrize(
        "exc_class",
        [
            PolicyLoadError,
            PolicyValidationError,
            ConfigurationError,
            AWSServiceError,
            InvalidPolicyFormatError,
            UnsupportedPolicyTypeError,
        ],
    )
    def test_all_exceptions_inherit_from_base(self, exc_class):
        assert issubclass(exc_class, IAMValidatorError)

    def test_invalid_policy_format_is_policy_load_error(self):
        assert issubclass(InvalidPolicyFormatError, PolicyLoadError)

    def test_unsupported_policy_type_is_policy_load_error(self):
        assert issubclass(UnsupportedPolicyTypeError, PolicyLoadError)

    def test_catch_base_catches_all(self):
        for exc_class in (
            PolicyLoadError,
            PolicyValidationError,
            ConfigurationError,
            AWSServiceError,
            InvalidPolicyFormatError,
            UnsupportedPolicyTypeError,
        ):
            with pytest.raises(IAMValidatorError):
                raise exc_class("test message")

    def test_catch_policy_load_catches_subtypes(self):
        for exc_class in (InvalidPolicyFormatError, UnsupportedPolicyTypeError):
            with pytest.raises(PolicyLoadError):
                raise exc_class("test message")


class TestExceptionMessages:
    """Verify exceptions carry informative messages."""

    def test_message_preserved(self):
        msg = "Unable to load policy from s3://bucket/key"
        exc = PolicyLoadError(msg)
        assert str(exc) == msg

    def test_base_exception_message(self):
        msg = "Something went wrong"
        exc = IAMValidatorError(msg)
        assert str(exc) == msg

    def test_aws_service_error_message(self):
        msg = "Failed to fetch service definition for s3"
        exc = AWSServiceError(msg)
        assert str(exc) == msg

    def test_configuration_error_message(self):
        msg = "Invalid config key: unknown_key"
        exc = ConfigurationError(msg)
        assert str(exc) == msg

    def test_exception_can_be_raised_and_caught(self):
        with pytest.raises(PolicyValidationError, match="validation failed"):
            raise PolicyValidationError("validation failed for policy.json")
