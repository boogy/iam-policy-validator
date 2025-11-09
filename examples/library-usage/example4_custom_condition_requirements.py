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

from iam_validator.core.config import CONDITION_REQUIREMENTS
from iam_validator.core.config.condition_requirements import (
    IAM_PASS_ROLE_REQUIREMENT,
    PREVENT_PUBLIC_IP,
    S3_SECURE_TRANSPORT,
    S3_WRITE_ORG_ID,
    SOURCE_IP_RESTRICTIONS,
)
from iam_validator.core.config.config_loader import ValidatorConfig

# ============================================================================
# Example 1: Use Default Requirements (Simplest)
# ============================================================================


def example1_use_defaults():
    """Use all requirements without any customization."""
    print("=" * 70)
    print("Example 1: Using All Requirements")
    print("=" * 70)

    # Just enable the check - uses all requirements automatically
    config_dict = {
        "action_condition_enforcement": {
            "enabled": True,
        }
    }

    config = ValidatorConfig(config_dict)

    # See what requirements are loaded
    reqs = config.config_dict["action_condition_enforcement"]["action_condition_requirements"]
    print(f"\n✓ Loaded {len(reqs)} requirements:")
    for req in reqs:
        actions = req.get("actions", req.get("action_patterns", ["N/A"]))
        severity = req.get("severity", "N/A")
        print(f"  - {actions[0]} (severity: {severity})")

    print("\n✓ Config ready to use!")
    return config


# ============================================================================
# Example 2: Pick Specific Requirements
# ============================================================================


def example2_pick_specific_requirements():
    """Pick specific requirements directly."""
    print("\n" + "=" * 70)
    print("Example 2: Picking Specific Requirements")
    print("=" * 70)

    # Pick exactly what you want by importing the constants
    requirements = [
        IAM_PASS_ROLE_REQUIREMENT,
        S3_SECURE_TRANSPORT,
        PREVENT_PUBLIC_IP,
    ]

    print(f"\n✓ Selected {len(requirements)} specific requirements")

    # Create config
    config_dict = {
        "action_condition_enforcement": {
            "enabled": True,
            "severity": "high",
            "action_condition_requirements": requirements,
        }
    }

    config = ValidatorConfig(config_dict)
    print("\n✓ Config ready with selected requirements!")
    return config


# ============================================================================
# Example 3: Subset of Defaults
# ============================================================================


def example3_subset_of_defaults():
    """Use a subset of default requirements."""
    print("\n" + "=" * 70)
    print("Example 3: Subset of Defaults")
    print("=" * 70)

    # Pick a subset of defaults for stricter security
    my_requirements = [
        IAM_PASS_ROLE_REQUIREMENT,  # Critical for privilege escalation
        S3_WRITE_ORG_ID,  # Organization restrictions for S3
        S3_SECURE_TRANSPORT,  # Enforce HTTPS
        PREVENT_PUBLIC_IP,  # Block public IPs
    ]

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

    # Get only high and critical severity requirements
    all_requirements = [
        IAM_PASS_ROLE_REQUIREMENT,
        S3_WRITE_ORG_ID,
        SOURCE_IP_RESTRICTIONS,
        S3_SECURE_TRANSPORT,
        PREVENT_PUBLIC_IP,
    ]

    high_risk_reqs = [req for req in all_requirements if req.get("severity") in ["high", "critical"]]

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

    # Start with all requirements
    import copy
    requirements = copy.deepcopy(CONDITION_REQUIREMENTS)

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

    # Development: Minimal requirements
    print("\n📦 Development Environment:")
    dev_reqs = [
        IAM_PASS_ROLE_REQUIREMENT,  # Just the critical ones
        S3_SECURE_TRANSPORT,
    ]
    print(f"  ✓ {len(dev_reqs)} requirements (minimal)")

    # Production: All requirements
    print("\n🏭 Production Environment:")
    import copy
    prod_reqs = copy.deepcopy(CONDITION_REQUIREMENTS)
    print(f"  ✓ {len(prod_reqs)} requirements (all)")

    print("\n✓ Environment configs ready!")


# ============================================================================
# Example 7: Explore Available Requirements
# ============================================================================


def example7_explore_requirements():
    """Explore what requirements are available."""
    print("\n" + "=" * 70)
    print("Example 7: Exploring Available Requirements")
    print("=" * 70)

    # All available requirements
    all_requirements = {
        "iam_pass_role": IAM_PASS_ROLE_REQUIREMENT,
        "s3_org_id": S3_WRITE_ORG_ID,
        "source_ip_restrictions": SOURCE_IP_RESTRICTIONS,
        "s3_secure_transport": S3_SECURE_TRANSPORT,
        "prevent_public_ip": PREVENT_PUBLIC_IP,
    }

    print(f"\n✓ Total available requirements: {len(all_requirements)}")

    # Show details for each
    print("\nAvailable Requirements:")
    print("-" * 70)

    for name, req in all_requirements.items():
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
    example2_pick_specific_requirements()
    example3_subset_of_defaults()
    example4_by_severity()
    example5_add_custom()
    example6_environment_configs()
    example7_explore_requirements()

    print("\n" + "=" * 70)
    print("✨ All examples completed!")
    print("=" * 70)
    print("\nKey Takeaways:")
    print("  • Use CONDITION_REQUIREMENTS for all requirements")
    print("  • Import specific requirement constants to pick what you need")
    print("  • Filter requirements by severity using list comprehensions")
    print("  • Add custom requirements inline for one-off cases")
    print("  • All requirements are simple Python dictionaries")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
