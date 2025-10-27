# Publishing Guide - IAM Policy Validator

This guide explains how to publish the IAM Policy Validator to PyPI.

## Automated Publishing (Recommended)

The project uses **trusted publishing** via GitHub Actions - **no API tokens required**.

### How It Works

1. **Push a version tag** to trigger the release workflow:
   ```bash
   git tag v1.1.1
   git push origin v1.1.1
   ```

2. **GitHub Actions automatically**:
   - Runs all tests and quality checks
   - Builds the package (wheel + source distribution)
   - Creates a GitHub Release with changelog
   - Publishes to PyPI using OIDC (no tokens needed)
   - Updates version tags (v1, v1.1)

### Prerequisites

1. **PyPI Trusted Publisher Configuration**
   - Already configured on PyPI for this project
   - Uses GitHub OIDC tokens (no secrets to manage)
   - See: https://docs.pypi.org/trusted-publishers/

2. **GitHub Repository Access**
   - Permissions to push tags
   - Actions enabled on the repository

## Manual Publishing (Development/Testing)

For local testing or manual releases, you can publish manually with an API token.

### Setup for Manual Publishing

1. **Get PyPI API Token**
   - Go to https://pypi.org/manage/account/token/
   - Create a new API token
   - Save securely (starts with `pypi-`)

2. **Configure Environment**
   ```bash
   export UV_PUBLISH_TOKEN="pypi-YOUR_TOKEN_HERE"
   ```

### Test on TestPyPI First (Recommended)

```bash
# Build and publish to TestPyPI
make publish-test

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ iam-policy-validator

# Test the installed package
iam-validator --help
```

### Manual Publish to Production PyPI

```bash
# Check current version
make version

# Build the package (creates dist/)
make build

# Publish to PyPI (requires UV_PUBLISH_TOKEN)
make publish

# Or publish directly with uv
uv publish
```

## Version Management

### Update Version

Edit `pyproject.toml`:
```toml
[project]
version = "0.2.0"  # Update this
```

### Semantic Versioning
- **0.1.0** → **0.1.1**: Bug fixes (patch)
- **0.1.0** → **0.2.0**: New features (minor)
- **0.1.0** → **1.0.0**: Breaking changes (major)

## Release Checklist

Before creating a release, ensure:

- [ ] All tests pass: `make test`
- [ ] Code is formatted: `make format`
- [ ] Linting passes: `make lint`
- [ ] Type checking passes: `make type-check`
- [ ] Version is updated in `pyproject.toml`
- [ ] README and DOCS are up to date
- [ ] All changes committed to main branch

## Complete Release Process (Automated)

```bash
# 1. Update version in pyproject.toml
# Example: version = "1.1.1"

# 2. Commit the version change
git add pyproject.toml
git commit -m "chore: Bump version to 1.1.1"
git push origin main

# 3. Run all quality checks locally
make check

# 4. Create and push the version tag
git tag v1.1.1
git push origin v1.1.1

# 5. GitHub Actions automatically:
#    - Runs tests
#    - Builds package
#    - Creates GitHub Release
#    - Publishes to PyPI (via trusted publishing)
#    - Updates major/minor tags (v1, v1.1)

# 6. Verify the release
# - Check GitHub: https://github.com/boogy/iam-policy-auditor/releases
# - Check PyPI: https://pypi.org/project/iam-policy-validator/
```

## Testing Before Release

```bash
# Test locally with your changes
uv sync
uv run iam-validator validate --path examples/policies/

# Run full test suite
make test

# Run all quality checks
make check
```

## Manual Publishing with uv

Only needed for testing or when automated publishing isn't available.

### Basic Usage

```bash
# Build first
uv build

# Publish (uses UV_PUBLISH_TOKEN env var)
uv publish

# Or provide token directly
uv publish --token pypi-YOUR_TOKEN

# Publish to TestPyPI
uv publish --publish-url https://test.pypi.org/legacy/
```

### Trusted Publishing (Local Testing)

If you've configured trusted publishing and want to test it locally:

```bash
# Build the package
uv build

# Publish using trusted publishing
uv publish --trusted-publishing always
```

Note: This only works if you've set up the proper OIDC configuration.

## Makefile Commands Reference

```bash
make help           # Show all available commands
make dev            # Install dev dependencies
make check          # Run all quality checks
make build          # Build distribution packages
make publish-test   # Publish to TestPyPI
make publish        # Publish to PyPI (with confirmation)
make clean          # Clean build artifacts
make version        # Show current version
```

## Troubleshooting

### "File already exists"
If you try to publish the same version twice:
- Update version in `pyproject.toml`
- Rebuild: `make build`
- Publish again

### Authentication Failed
- Check your token is correct
- Ensure token has proper scope
- Token format: `pypi-AgEIcHlwaS5vcmc...`

### Package Not Found After Publishing
- Wait 1-2 minutes for PyPI to index
- Check package name: https://pypi.org/project/iam-policy-validator/

### Missing Dependencies in Published Package
- Verify `dependencies` in `pyproject.toml`
- Check `[tool.hatch.build.targets.wheel]` section

## Security Best Practices

### Automated Publishing (Trusted Publishers)

✅ **Benefits of Trusted Publishing:**
- No API tokens to manage or rotate
- No secrets to store in GitHub
- Automatic authentication via OIDC
- Scoped to specific repository and workflow
- More secure than long-lived API tokens

### Manual Publishing

If you must use API tokens:

1. **Never commit tokens to git**
   ```bash
   # Add to .gitignore
   echo ".env" >> .gitignore
   echo "*.token" >> .gitignore
   ```

2. **Use separate tokens for TestPyPI and PyPI**

3. **Rotate tokens periodically**

4. **Use scoped tokens** (per-project) when possible

5. **Store tokens in password manager or keyring**

## After Publishing

The automated workflow handles most post-publishing tasks, but you should:

1. **Verify on PyPI**: https://pypi.org/project/iam-policy-validator/

2. **Verify GitHub Release**: https://github.com/boogy/iam-policy-auditor/releases

3. **Test installation**:
   ```bash
   pip install iam-policy-validator==1.1.1
   iam-validator --version
   ```

4. **Verify action tags updated**:
   ```bash
   # Check that v1 and v1.1 tags were updated
   git fetch --tags
   git log --oneline --decorate | head -5
   ```

5. **Announce** (optional):
   - Twitter/social media
   - Reddit (r/Python, r/aws)
   - Dev.to blog post

## Resources

- [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [uv documentation](https://docs.astral.sh/uv/)
- [GitHub OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Semantic Versioning](https://semver.org/)
- [Python classifiers](https://pypi.org/classifiers/)
