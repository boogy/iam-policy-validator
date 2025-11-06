#!/usr/bin/env python
"""
Example 4: Custom Condition Requirements

This example demonstrates how to use the modular condition requirements
system to customize action_condition_enforcement_check without complex YAML.

Benefits:
- Easy to read and maintain
- Type-safe with IDE support
- Pick and choose requirements by name
- Add custom requirements easily
"""

from iam_validator.core.config import (
    get_all_requirement_names,
    get_default_requirements,
    get_requirement,
    get_requirements_by_names,
    get_requirements_by_severity,
)
from iam_validator.core.config_loader import ValidatorConfig

# ============================================================================
# Example 1: Use Default Requirements (Simplest)
# ============================================================================


def example1_use_defaults():
    """Use default requirements without any customization."""
    print("=" * 70)
    print("Example 1: Using Default Requirements")
    print("=" * 70)

    # Just enable the check - uses defaults automatically
    config_dict = {
        "action_condition_enforcement": {
            "enabled": True,
        }
    }

    config = ValidatorConfig(config_dict)

    # See what requirements are loaded
    reqs = config.config_dict["action_condition_enforcement"]["action_condition_requirements"]
    print(f"\n✓ Loaded {len(reqs)} default requirements:")
    for req in reqs:
        actions = req.get("actions", req.get("action_patterns", ["N/A"]))
        severity = req.get("severity", "N/A")
        print(f"  - {actions[0]} (severity: {severity})")

    print("\n✓ Config ready to use!")
    return config


# ============================================================================
# Example 2: Add Optional Requirements
# ============================================================================


def example2_add_optional():
    """Start with defaults and add optional requirements."""
    print("\n" + "=" * 70)
    print("Example 2: Adding Optional Requirements")
    print("=" * 70)

    # Get defaults
    requirements = get_default_requirements()
    print(f"\n✓ Started with {len(requirements)} default requirements")

    # Add optional requirements
    requirements.append(get_requirement("s3_destructive_mfa"))
    requirements.append(get_requirement("ec2_tag_requirements"))
    requirements.append(get_requirement("rds_tag_requirements"))

    print("✓ Added 3 optional requirements")
    print(f"✓ Total: {len(requirements)} requirements")

    # Create config
    config_dict = {
        "action_condition_enforcement": {
            "enabled": True,
            "severity": "high",
            "action_condition_requirements": requirements,
        }
    }

    config = ValidatorConfig(config_dict)
    print("\n✓ Config ready with enhanced requirements!")
    return config


# ============================================================================
# Example 3: Build Custom Requirement Set
# ============================================================================


def example3_custom_set():
    """Build a custom set of requirements by name."""
    print("\n" + "=" * 70)
    print("Example 3: Custom Requirement Set")
    print("=" * 70)

    # Pick exactly what you want
    my_requirements = get_requirements_by_names(
        [
            "iam_pass_role",  # Critical for privilege escalation
            "iam_permissions_boundary",  # IAM boundary enforcement
            "s3_destructive_mfa",  # MFA for S3 deletes
            "ec2_tag_requirements",  # ABAC tagging
        ]
    )

    print(f"\n✓ Built custom set with {len(my_requirements)} requirements:")
    for req in my_requirements:
        actions = req.get("actions", req.get("action_patterns", ["N/A"]))
        print(f"  - {actions[0]}")

    config_dict = {
        "action_condition_enforcement": {"action_condition_requirements": my_requirements}
    }

    config = ValidatorConfig(config_dict)
    print("\n✓ Custom config ready!")
    return config


# ============================================================================
# Example 4: Filter by Severity
# ============================================================================


def example4_by_severity():
    """Get requirements filtered by severity level."""
    print("\n" + "=" * 70)
    print("Example 4: Filter by Severity")
    print("=" * 70)

    # Get only high and critical severity
    high_risk_reqs = get_requirements_by_severity(min_severity="high")

    print(f"\n✓ Found {len(high_risk_reqs)} high+ severity requirements:")
    for req in high_risk_reqs:
        # Handle both list and dict (none_of) formats
        actions_val = req.get("actions")
        if isinstance(actions_val, list):
            action_str = actions_val[0] if actions_val else "N/A"
        elif isinstance(actions_val, dict):
            action_str = "complex"
        else:
            action_patterns = req.get("action_patterns", [])
            action_str = action_patterns[0] if action_patterns else "N/A"

        severity = req.get("severity", "N/A")
        print(f"  - {action_str} (severity: {severity})")

    config_dict = {
        "action_condition_enforcement": {"action_condition_requirements": high_risk_reqs}
    }

    config = ValidatorConfig(config_dict)
    print("\n✓ High-severity config ready!")
    return config


# ============================================================================
# Example 5: Add Custom Inline Requirement
# ============================================================================


def example5_add_custom():
    """Add your own custom requirement inline."""
    print("\n" + "=" * 70)
    print("Example 5: Adding Custom Inline Requirement")
    print("=" * 70)

    # Start with defaults
    requirements = get_default_requirements()

    # Add your own custom requirement
    custom_requirement = {
        "actions": ["lambda:CreateFunction", "lambda:UpdateFunctionCode"],
        "severity": "high",
        "required_conditions": [
            {
                "condition_key": "lambda:VpcConfig",
                "description": "Lambda functions must be deployed in VPC for security",
                "example": """{
  "Condition": {
    "StringLike": {
      "lambda:VpcConfig": "*"
    }
  }
}""",
            }
        ],
    }

    requirements.append(custom_requirement)

    print("\n✓ Added custom Lambda VPC requirement")
    print(f"✓ Total: {len(requirements)} requirements")

    config_dict = {
        "action_condition_enforcement": {"action_condition_requirements": requirements}
    }

    config = ValidatorConfig(config_dict)
    print("\n✓ Config with custom requirement ready!")
    return config


# ============================================================================
# Example 6: Production vs Development Configs
# ============================================================================


def example6_environment_configs():
    """Different configs for different environments."""
    print("\n" + "=" * 70)
    print("Example 6: Environment-Specific Configurations")
    print("=" * 70)

    # Development: Relaxed requirements
    print("\n📦 Development Environment:")
    dev_reqs = get_requirements_by_names(
        [
            "iam_pass_role",  # Just the critical ones
            "s3_secure_transport",
        ]
    )
    print(f"  ✓ {len(dev_reqs)} requirements (relaxed)")

    # Production: Strict requirements
    print("\n🏭 Production Environment:")
    prod_reqs = get_requirements_by_names(
        [
            "iam_pass_role",
            "iam_permissions_boundary",
            "s3_destructive_mfa",
            "s3_secure_transport",
            "ec2_tag_requirements",
            "rds_tag_requirements",
        ]
    )
    print(f"  ✓ {len(prod_reqs)} requirements (strict)")

    print("\n✓ Environment configs ready!")


# ============================================================================
# Example 7: Explore Available Requirements
# ============================================================================


def example7_explore_requirements():
    """Explore what requirements are available."""
    print("\n" + "=" * 70)
    print("Example 7: Exploring Available Requirements")
    print("=" * 70)

    # Get all requirement names
    all_names = get_all_requirement_names()
    print(f"\n✓ Total available requirements: {len(all_names)}")

    # Show details for each
    print("\nAvailable Requirements:")
    print("-" * 70)

    for name in all_names:
        req = get_requirement(name)

        # Handle actions (list, dict, or None)
        actions_val = req.get("actions")
        if isinstance(actions_val, list):
            action_str = actions_val[0] if actions_val else "N/A"
        elif isinstance(actions_val, dict):
            action_str = "(complex condition)"
        else:
            action_patterns = req.get("action_patterns", [])
            action_str = action_patterns[0] if action_patterns else "N/A"

        severity = req.get("severity", "N/A")
        description = req.get("description", "N/A")

        # Get first condition key
        conds = req.get("required_conditions", [])
        if isinstance(conds, list) and conds:
            cond_key = conds[0].get("condition_key", "N/A")
        elif isinstance(conds, dict):
            # Handle any_of/all_of/none_of
            if "all_of" in conds:
                cond_key = f"all_of ({len(conds['all_of'])} conditions)"
            elif "any_of" in conds:
                cond_key = f"any_of ({len(conds['any_of'])} conditions)"
            elif "none_of" in conds:
                cond_key = f"none_of ({len(conds['none_of'])} conditions)"
            else:
                cond_key = "N/A"
        else:
            cond_key = "N/A"

        print(f"\n{name}:")
        print(f"  Actions: {action_str}")
        print(f"  Severity: {severity}")
        print(f"  Description: {description}")
        print(f"  Condition: {cond_key}")


# ============================================================================
# Main
# ============================================================================


def main():
    """Run all examples."""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║           Custom Condition Requirements Examples                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
""")

    # Run examples
    example1_use_defaults()
    example2_add_optional()
    example3_custom_set()
    example4_by_severity()
    example5_add_custom()
    example6_environment_configs()
    example7_explore_requirements()

    print("\n" + "=" * 70)
    print("✨ All examples completed!")
    print("=" * 70)
    print("\nKey Takeaways:")
    print("  • Use get_default_requirements() for quick setup")
    print("  • Use get_requirements_by_names() to pick specific requirements")
    print("  • Use get_requirements_by_severity() to filter by risk level")
    print("  • Add custom requirements inline for one-off cases")
    print("  • All requirements are documented and easy to understand")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
