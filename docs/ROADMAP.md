# Roadmap & Future Improvements

This document tracks planned enhancements and features for the IAM Policy Validator.

## 🎯 Planned Features

### High Priority

#### 1. NotResource Support
**Status:** Planned
**Description:** Add validation support for `NotResource` elements in IAM policies.

Currently, the validator focuses on `Resource` elements. Adding `NotResource` support would enable:
- Validation of deny statements using resource exclusions
- Detection of overly broad NotResource patterns
- Best practices enforcement for NotResource usage

**Use Cases:**
```json
{
  "Effect": "Deny",
  "Action": "s3:*",
  "NotResource": "arn:aws:s3:::safe-bucket/*"
}
```

**Implementation Notes:**
- Validate NotResource ARN format (similar to Resource validation)
- Check for security anti-patterns (e.g., NotResource: "*" is ineffective)
- Ensure NotResource is only used with Deny statements (AWS best practice)
- Add tests for NotResource in all policy types

---

#### 2. NotAction Support
**Status:** Planned
**Description:** Add validation support for `NotAction` elements in IAM policies.

Currently, the validator validates `Action` elements. Adding `NotAction` support would enable:
- Validation of deny statements using action exclusions
- Detection of overly permissive NotAction patterns
- Security checks for dangerous NotAction combinations

**Use Cases:**
```json
{
  "Effect": "Deny",
  "NotAction": [
    "iam:Get*",
    "iam:List*"
  ],
  "Resource": "*"
}
```

**Implementation Notes:**
- Validate NotAction against AWS service definitions
- Check for security risks (e.g., NotAction with minimal exclusions)
- Ensure NotAction is primarily used with Deny statements
- Handle wildcard expansion in NotAction
- Add tests for NotAction validation

**Constraints:**
- NotAction is NOT supported in Resource Control Policies (RCPs)
- NotPrincipal is NOT supported in RCPs

---

#### 3. Deny Statement Validation with NotAction/NotResource
**Status:** Planned
**Description:** Enhanced validation for Deny statements using NotAction or NotResource.

This would provide specialized checks for deny-based policies:
- Validate that NotAction/NotResource are used appropriately with Deny
- Detect unintended permission grants through NotAction/NotResource
- Check for common mistakes (e.g., using Allow with NotAction)
- Ensure proper least-privilege principles

**Security Checks:**
```yaml
# Example checks to implement
deny_with_not_action:
  enabled: true
  severity: high
  description: "Validates proper use of NotAction in Deny statements"

deny_with_not_resource:
  enabled: true
  severity: high
  description: "Validates proper use of NotResource in Deny statements"
```

**Examples of Issues to Detect:**
```json
// ❌ BAD: Allow with NotAction (usually a mistake)
{
  "Effect": "Allow",
  "NotAction": "s3:DeleteBucket",
  "Resource": "*"
}

// ✅ GOOD: Deny with NotAction
{
  "Effect": "Deny",
  "NotAction": [
    "iam:Get*",
    "iam:List*"
  ],
  "Resource": "*"
}

// ⚠️ WARNING: Very broad NotResource (denies almost everything)
{
  "Effect": "Deny",
  "Action": "s3:*",
  "NotResource": "arn:aws:s3:::single-bucket/*"
}
```

**Implementation Notes:**
- Add check for Allow + NotAction/NotResource combinations (usually unintended)
- Warn when NotAction/NotResource has minimal exclusions (overly broad deny)
- Validate that NotAction actions exist in AWS services
- Provide suggestions for refactoring to more explicit policies

---

### Medium Priority

#### 4. Policy Simulation Integration
**Status:** Future consideration
**Description:** Integration with AWS IAM Policy Simulator API for runtime behavior testing.

This would enable:
- Testing policies against specific actions and resources
- Validating effective permissions with multiple policies
- Context-aware validation (e.g., with session tags, resource tags)

---

#### 5. Cross-Policy Analysis
**Status:** Future consideration
**Description:** Analyze multiple policies together for conflicts and overlaps.

Features:
- Detect conflicting Allow/Deny statements across policies
- Find redundant permissions
- Identify permission gaps
- Visualize effective permissions from multiple policies

---

#### 6. Historical Policy Comparison
**Status:** Future consideration
**Description:** Track policy changes over time and analyze permission drift.

Features:
- Compare policy versions
- Detect permission creep
- Generate permission change reports
- Integration with git history

---

### Low Priority

#### 7. Enhanced Privilege Escalation Detection
**Status:** Future consideration
**Description:** More sophisticated detection of privilege escalation paths.

Would include:
- Multi-step escalation path detection
- Resource-specific escalation analysis
- Cross-service escalation patterns

---

#### 8. Custom Action Groups
**Status:** Future consideration
**Description:** Allow users to define custom action groups for their organization.

Example:
```yaml
custom_action_groups:
  database_write:
    - "dynamodb:PutItem"
    - "dynamodb:UpdateItem"
    - "dynamodb:DeleteItem"
    - "rds:ModifyDBInstance"
```

---

## 🐛 Known Limitations

### Current Limitations

1. **NotAction/NotResource Not Validated**
   - These elements are currently skipped in validation
   - No security checks for their usage patterns
   - Planned for future release (see above)

2. **RCP Validation Limitations**
   - NotAction and NotPrincipal are not supported (per AWS RCP constraints)
   - Only 5 services supported: s3, sts, sqs, secretsmanager, kms

3. **Wildcard Expansion Scope**
   - Wildcard expansion for condition key validation is limited to actions
   - Does not expand wildcards in NotAction

4. **Policy Simulation**
   - Does not perform runtime simulation (only static analysis)
   - Cannot test effective permissions with session context

---

## 📝 Contributing

Have ideas for improvements? We'd love to hear them!

1. **Check existing issues:** [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues)
2. **Discuss proposals:** [GitHub Discussions](https://github.com/boogy/iam-policy-validator/discussions)
3. **Submit PRs:** See [CONTRIBUTING.md](../CONTRIBUTING.md)

### How to Propose a Feature

1. Open a GitHub Discussion with:
   - Clear use case description
   - Example policies showing the need
   - Expected behavior
   - Impact assessment (security, performance, usability)

2. For complex features, we may request:
   - Design document
   - Proof of concept
   - Test cases

---

## 🎯 Completed Features

Features that were once on the roadmap and are now implemented:

### v1.5.0
- ✅ Modular Python configuration system (5-10x faster)
- ✅ Split security checks into individual modules:
  - `wildcard_action` - Check for wildcard actions (Action: "*")
  - `wildcard_resource` - Check for wildcard resources (Resource: "*")
  - `service_wildcard` - Check for service-level wildcards (e.g., "s3:*")
  - `sensitive_action` - Check sensitive actions without conditions
  - `full_wildcard` - Check for Action:* + Resource:* (critical)
- ✅ GitHub Action enhancements:
  - RESOURCE_CONTROL_POLICY support
  - github-summary input for Actions job summary
- ✅ 27 new resource policy test examples
- ✅ Comprehensive roadmap documentation
- ✅ 4 new documentation files (ROADMAP, modular-configuration, condition-requirements, aws-api-configuration)

### v1.4.0
- ✅ Resource Control Policy (RCP) support with 8 validation checks
- ✅ Enhanced principal validation (`principal_validation` check):
  - Blocked principals (e.g., public access "*")
  - Allowed principals whitelist
  - Required conditions for specific principals (simple & advanced formats)
  - Service principal validation
  - Principal condition requirements (all_of/any_of/none_of logic)
- ✅ SID format validation (alphanumeric + hyphens/underscores only)
- ✅ Policy type validation (`policy_type_validation` check) for all 4 types
- ✅ 6 RCP test policies, 3 SCP test policies

### v1.3.0
- ✅ Modular Python configuration system
- ✅ Condition requirement templates

### v1.2.0
- ✅ Smart IAM policy detection and filtering
- ✅ YAML policy support
- ✅ Streaming mode for large policy sets

### v1.1.0
- ✅ Split security checks into individual modules
- ✅ Configurable check system

---

## 📅 Release Planning

Releases follow semantic versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes, major architectural changes
- **MINOR**: New features, significant enhancements
- **PATCH**: Bug fixes, documentation updates, minor improvements

**Estimated Timeline for Planned Features:**
- NotResource/NotAction support: v1.5.0 or v1.6.0
- Deny statement validation: v1.6.0 or v1.7.0
- Policy simulation: v2.0.0 (requires major architectural changes)

*Note: Timelines are estimates and subject to change based on community feedback and priorities.*

---

## 🤝 Support

- **Questions:** [GitHub Discussions](https://github.com/boogy/iam-policy-validator/discussions)
- **Bug Reports:** [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues)
- **Feature Requests:** [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues/new?template=feature_request.md)
