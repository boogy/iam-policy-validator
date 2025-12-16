---
title: GitLab CI
description: Integrate IAM Policy Validator with GitLab CI/CD
---

# GitLab CI Integration

Integrate IAM Policy Validator into your GitLab CI/CD pipelines.

## Basic Configuration

Add to your `.gitlab-ci.yml`:

```yaml
validate-iam-policies:
  image: python:3.12-slim
  stage: test
  before_script:
    - pip install iam-policy-validator
  script:
    - iam-validator validate --path ./policies/ --format json
  rules:
    - changes:
        - "policies/**/*"
        - "**/*.json"
```

## With Configuration File

```yaml
validate-iam-policies:
  image: python:3.12-slim
  stage: test
  before_script:
    - pip install iam-policy-validator
  script:
    - iam-validator validate --path ./policies/ --config iam-validator.yaml
  artifacts:
    reports:
      junit: validation-report.xml
    when: always
```

## SARIF Report for Security Dashboard

```yaml
iam-security-scan:
  image: python:3.12-slim
  stage: test
  before_script:
    - pip install iam-policy-validator
  script:
    - iam-validator validate --path ./policies/ --format sarif > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Merge Request Comments

To post comments on merge requests, use the GitLab API:

```yaml
validate-and-comment:
  image: python:3.12-slim
  stage: test
  before_script:
    - pip install iam-policy-validator
  script:
    - |
      RESULT=$(iam-validator validate --path ./policies/ --format json)
      if [ $? -ne 0 ]; then
        curl --request POST \
          --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
          --data "body=IAM Policy Validation Failed" \
          "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
        exit 1
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

## Cache for Performance

```yaml
validate-iam-policies:
  image: python:3.12-slim
  stage: test
  cache:
    key: iam-validator-cache
    paths:
      - .cache/
  variables:
    IAM_VALIDATOR_CACHE_DIR: .cache/
  before_script:
    - pip install iam-policy-validator
    - iam-validator download-services
  script:
    - iam-validator validate --path ./policies/
```
