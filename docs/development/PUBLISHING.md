# Publishing Guide - IAM Policy Validator

This guide explains how to publish the IAM Policy Validator to PyPI using `uv`.

## Prerequisites

1. **PyPI Account**
   - Create account at https://pypi.org/account/register/
   - Verify your email address

2. **API Token**
   - Go to https://pypi.org/manage/account/token/
   - Create a new API token
   - Scope: "Entire account" or specific to this project
   - Save the token securely (starts with `pypi-`)

3. **Configure uv with PyPI Token**
   ```bash
   # Set as environment variable (recommended)
   export UV_PUBLISH_TOKEN="pypi-YOUR_TOKEN_HERE"

   # Or use keyring (more secure)
   uv publish --token $(keyring get pypi token)
   ```

## Publishing Workflow

### 1. First Time Setup

```bash
# Install development dependencies
make dev

# Run all quality checks
make check
```

### 2. Test on TestPyPI First (Recommended)

```bash
# Build and publish to TestPyPI
make publish-test

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ iam-policy-validator

# Test the installed package
iam-validator --help
```

### 3. Publish to Production PyPI

```bash
# Check current version
make version

# Build the package (creates dist/)
make build

# Publish to PyPI (with confirmation prompt)
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

## Publishing Checklist

Before publishing, ensure:

- [ ] All tests pass: `make test`
- [ ] Code is formatted: `make format`
- [ ] Linting passes: `make lint`
- [ ] Type checking passes: `make type-check`
- [ ] Version is updated in `pyproject.toml`
- [ ] CHANGELOG is updated (if you have one)
- [ ] README is up to date
- [ ] Tested on TestPyPI first
- [ ] Git commit and tag: `git tag v0.1.0`

## Complete Publishing Process

```bash
# 1. Update version in pyproject.toml
# 2. Run all checks
make check

# 3. Clean previous builds
make clean

# 4. Test on TestPyPI
export UV_PUBLISH_TOKEN="pypi-YOUR_TESTPYPI_TOKEN"
make publish-test

# 5. Test installation
pip install --index-url https://test.pypi.org/simple/ iam-policy-validator

# 6. If all good, publish to production PyPI
export UV_PUBLISH_TOKEN="pypi-YOUR_PYPI_TOKEN"
make publish

# 7. Create git tag
git tag v0.1.0
git push origin v0.1.0

# 8. Create GitHub release
gh release create v0.1.0 --generate-notes
```

## Using uv publish Directly

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

### With Custom Registry

```bash
# Private PyPI registry
uv publish --publish-url https://your-registry.com/simple/ --token YOUR_TOKEN
```

## Environment Variables

```bash
# PyPI token (production)
export UV_PUBLISH_TOKEN="pypi-YOUR_PRODUCTION_TOKEN"

# TestPyPI token (testing)
export UV_PUBLISH_TOKEN="pypi-YOUR_TESTPYPI_TOKEN"

# Or store in .env (don't commit!)
echo "UV_PUBLISH_TOKEN=pypi-YOUR_TOKEN" > .env
source .env
```

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

1. **Verify on PyPI**: https://pypi.org/project/iam-policy-validator/

2. **Test installation**:
   ```bash
   pip install iam-policy-validator
   iam-validator --version
   ```

3. **Update GitHub Release** with:
   - Release notes
   - Installation instructions
   - Link to PyPI

4. **Announce** (optional):
   - Twitter/social media
   - Reddit (r/Python, r/aws)
   - Dev.to blog post

## Resources

- [uv documentation](https://docs.astral.sh/uv/)
- [PyPI packaging guide](https://packaging.python.org/tutorials/packaging-projects/)
- [Semantic Versioning](https://semver.org/)
- [Python classifiers](https://pypi.org/classifiers/)
