"""Tests for the mcp/auth.py auth provider factory."""

import asyncio
import json

import pytest

from iam_validator.mcp.auth import get_auth_provider
from iam_validator.mcp.settings import ServerSettings

pytest.importorskip("fastmcp")

from fastmcp.server.auth.providers.jwt import RSAKeyPair, StaticTokenVerifier  # noqa: E402


def run(coro):
    return asyncio.run(coro)


class TestNoneProvider:
    def test_local_none_returns_none(self):
        settings = ServerSettings(mode="local", auth="none")
        assert get_auth_provider(settings) is None

    def test_hosted_none_implicit_fails_to_start(self):
        # ServerSettings itself already refuses this combination (auth_explicitly_set
        # defaults to False), so build it via model_construct to bypass that guard and
        # prove auth.py enforces the rule independently, in case a caller mutates a
        # settings instance in place after construction.
        settings = ServerSettings.model_construct(mode="hosted", auth="none", auth_explicitly_set=False)
        with pytest.raises(SystemExit) as exc_info:
            get_auth_provider(settings)
        assert exc_info.value.code != 0

    def test_hosted_none_explicit_starts(self):
        settings = ServerSettings(mode="hosted", auth="none", auth_explicitly_set=True)
        assert get_auth_provider(settings) is None


class TestHostedOpenGuardActuallyGuards:
    def test_guard_is_reachable_and_load_bearing(self):
        """Same case as test_hosted_none_implicit_fails_to_start, phrased to make clear
        this is the regression the "hidden, not refused" open-hosted-server risk needs.
        Removing the `if settings.mode == "hosted" and not settings.auth_explicitly_set`
        branch in auth.py's get_auth_provider() makes this test fail (verified manually
        per the task's verification instructions, then restored)."""
        settings = ServerSettings.model_construct(mode="hosted", auth="none", auth_explicitly_set=False)
        with pytest.raises(SystemExit):
            get_auth_provider(settings)


class TestTokenProvider:
    def test_rejects_token_from_cli_flag(self, monkeypatch, capsys):
        # Both sources present (not absent) so a passing test can only mean the
        # flag trip-wire fired first, never the "no source configured" path.
        monkeypatch.setenv(
            "IAM_VALIDATOR_MCP_AUTH_TOKENS",
            json.dumps({"tok-fake-present": {"client_id": "client-a", "scopes": []}}),
        )
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_TOKEN_FILE", raising=False)
        settings = ServerSettings(auth="token")

        with pytest.raises(SystemExit) as exc_info:
            get_auth_provider(settings, token_cli_flag="s3cr3t-from-argv")

        assert exc_info.value.code != 0
        stderr = capsys.readouterr().err
        assert "command-line flag" in stderr
        assert "s3cr3t-from-argv" not in stderr

    def test_no_source_configured_fails(self, monkeypatch):
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_TOKEN_FILE", raising=False)
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_TOKENS", raising=False)
        settings = ServerSettings(auth="token")
        with pytest.raises(SystemExit):
            get_auth_provider(settings)

    def test_both_sources_configured_fails(self, monkeypatch, tmp_path):
        token_file = tmp_path / "tokens.json"
        token_file.write_text(json.dumps({"tok-fake-abc123": {"client_id": "c1", "scopes": []}}))
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_TOKEN_FILE", str(token_file))
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_TOKENS", "{}")
        settings = ServerSettings(auth="token")
        with pytest.raises(SystemExit):
            get_auth_provider(settings)

    def test_accepts_token_from_file(self, monkeypatch, tmp_path):
        token_file = tmp_path / "tokens.json"
        token_file.write_text(json.dumps({"tok-fake-fromfile": {"client_id": "client-a", "scopes": ["iam:validate"]}}))
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_TOKENS", raising=False)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_TOKEN_FILE", str(token_file))
        settings = ServerSettings(auth="token")

        provider = get_auth_provider(settings)

        assert isinstance(provider, StaticTokenVerifier)
        access_token = run(provider.verify_token("tok-fake-fromfile"))
        assert access_token is not None
        assert access_token.client_id == "client-a"

    def test_accepts_token_from_env(self, monkeypatch):
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_TOKEN_FILE", raising=False)
        monkeypatch.setenv(
            "IAM_VALIDATOR_MCP_AUTH_TOKENS",
            json.dumps({"tok-fake-fromenv": {"client_id": "client-b", "scopes": []}}),
        )
        settings = ServerSettings(auth="token")

        provider = get_auth_provider(settings)

        assert isinstance(provider, StaticTokenVerifier)
        access_token = run(provider.verify_token("tok-fake-fromenv"))
        assert access_token is not None
        assert access_token.client_id == "client-b"

    def test_unknown_token_rejected(self, monkeypatch):
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_TOKEN_FILE", raising=False)
        monkeypatch.setenv(
            "IAM_VALIDATOR_MCP_AUTH_TOKENS",
            json.dumps({"tok-fake-known": {"client_id": "client-c", "scopes": []}}),
        )
        settings = ServerSettings(auth="token")
        provider = get_auth_provider(settings)
        assert run(provider.verify_token("tok-fake-unknown")) is None


class TestJwtProvider:
    def test_scope_present_succeeds_and_missing_scope_denied(self, monkeypatch):
        keypair = RSAKeyPair.generate()
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_JWT_PUBLIC_KEY", keypair.public_key)
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_JWT_JWKS_URI", raising=False)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_JWT_ISSUER", "https://issuer.example.test")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_JWT_AUDIENCE", "iam-validator-mcp")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_REQUIRED_SCOPES", "iam:validate")
        settings = ServerSettings(auth="jwt")

        provider = get_auth_provider(settings)

        good_token = keypair.create_token(
            issuer="https://issuer.example.test",
            audience="iam-validator-mcp",
            scopes=["iam:validate"],
        )
        assert run(provider.verify_token(good_token)) is not None

        bad_token = keypair.create_token(
            issuer="https://issuer.example.test",
            audience="iam-validator-mcp",
            scopes=["iam:query"],
        )
        assert run(provider.verify_token(bad_token)) is None

    def test_requires_jwks_uri_or_public_key_not_both_or_neither(self, monkeypatch):
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_JWT_JWKS_URI", raising=False)
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_JWT_PUBLIC_KEY", raising=False)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_JWT_ISSUER", "https://issuer.example.test")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_JWT_AUDIENCE", "iam-validator-mcp")
        settings = ServerSettings(auth="jwt")
        with pytest.raises(SystemExit):
            get_auth_provider(settings)

    def test_requires_issuer_and_audience(self, monkeypatch):
        keypair = RSAKeyPair.generate()
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_JWT_PUBLIC_KEY", keypair.public_key)
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_JWT_ISSUER", raising=False)
        monkeypatch.delenv("IAM_VALIDATOR_MCP_AUTH_JWT_AUDIENCE", raising=False)
        settings = ServerSettings(auth="jwt")
        with pytest.raises(SystemExit):
            get_auth_provider(settings)


class TestUnknownAuth:
    def test_unknown_provider_name_fails(self):
        settings = ServerSettings(auth="not-a-real-provider")
        with pytest.raises(SystemExit):
            get_auth_provider(settings)


class TestIdpProviders:
    """Construction smoke tests for the six IdP builders -- each must actually
    produce a provider from get_auth_provider(), not just avoid raising inside
    the builder function itself."""

    def _clear_idp_env(self, monkeypatch):
        for name in (
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GITHUB_CLIENT_ID",
            "GITHUB_CLIENT_SECRET",
            "KEYCLOAK_REALM_URL",
            "KEYCLOAK_AUDIENCE",
            "AUTH0_CONFIG_URL",
            "AUTH0_CLIENT_ID",
            "AUTH0_CLIENT_SECRET",
            "AUTH0_AUDIENCE",
            "WORKOS_AUTHKIT_DOMAIN",
            "REQUIRED_SCOPES",
            "BASE_URL",
        ):
            monkeypatch.delenv(f"IAM_VALIDATOR_MCP_AUTH_{name}", raising=False)

    def test_azure_missing_required_scopes_fails(self, monkeypatch, capsys):
        self._clear_idp_env(monkeypatch)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_AZURE_CLIENT_ID", "fake-client-id")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_AZURE_TENANT_ID", "fake-tenant-id")
        settings = ServerSettings(auth="azure")

        with pytest.raises(SystemExit):
            get_auth_provider(settings)

        stderr = capsys.readouterr().err
        assert "IAM_VALIDATOR_MCP_AUTH_REQUIRED_SCOPES" in stderr
        assert "non-OIDC" in stderr

    def test_azure_with_non_oidc_scope_constructs(self, monkeypatch):
        self._clear_idp_env(monkeypatch)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_AZURE_CLIENT_ID", "fake-client-id")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_AZURE_CLIENT_SECRET", "fake-secret")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_AZURE_TENANT_ID", "fake-tenant-id")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_REQUIRED_SCOPES", "api://fake-app/access")
        settings = ServerSettings(auth="azure")

        provider = get_auth_provider(settings)

        assert provider is not None

    def test_google_builder_constructs(self, monkeypatch):
        self._clear_idp_env(monkeypatch)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_GOOGLE_CLIENT_ID", "fake-client-id")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_GOOGLE_CLIENT_SECRET", "fake-secret")
        settings = ServerSettings(auth="google")

        assert get_auth_provider(settings) is not None

    def test_github_builder_constructs(self, monkeypatch):
        self._clear_idp_env(monkeypatch)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_GITHUB_CLIENT_ID", "fake-client-id")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_GITHUB_CLIENT_SECRET", "fake-secret")
        settings = ServerSettings(auth="github")

        assert get_auth_provider(settings) is not None

    def test_keycloak_builder_constructs(self, monkeypatch):
        self._clear_idp_env(monkeypatch)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_KEYCLOAK_REALM_URL", "https://keycloak.example.test/realms/fake")
        settings = ServerSettings(auth="keycloak")

        assert get_auth_provider(settings) is not None

    def test_workos_builder_constructs(self, monkeypatch):
        self._clear_idp_env(monkeypatch)
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_WORKOS_AUTHKIT_DOMAIN", "https://fake.authkit.app")
        settings = ServerSettings(auth="workos")

        assert get_auth_provider(settings) is not None

    def test_auth0_builder_constructs(self, monkeypatch):
        from fastmcp.server.auth import oidc_proxy as oidc_proxy_mod

        class _FakeResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {
                    "issuer": "https://fake.auth0.test/",
                    "authorization_endpoint": "https://fake.auth0.test/authorize",
                    "token_endpoint": "https://fake.auth0.test/oauth/token",
                    "jwks_uri": "https://fake.auth0.test/.well-known/jwks.json",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }

        monkeypatch.setattr(oidc_proxy_mod.httpx2, "get", lambda *a, **k: _FakeResponse())
        self._clear_idp_env(monkeypatch)
        monkeypatch.setenv(
            "IAM_VALIDATOR_MCP_AUTH_AUTH0_CONFIG_URL", "https://fake.auth0.test/.well-known/openid-configuration"
        )
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_AUTH0_CLIENT_ID", "fake-client-id")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_AUTH0_CLIENT_SECRET", "fake-secret")
        monkeypatch.setenv("IAM_VALIDATOR_MCP_AUTH_AUTH0_AUDIENCE", "https://fake.auth0.test/api")
        settings = ServerSettings(auth="auth0")

        assert get_auth_provider(settings) is not None


class TestAwsGatewayProviderGate:
    def test_default_refuses(self):
        settings = ServerSettings(auth="aws-gateway")
        with pytest.raises(SystemExit) as exc_info:
            get_auth_provider(settings)
        assert exc_info.value.code != 0

    def test_explicit_false_refuses(self):
        settings = ServerSettings(auth="aws-gateway")
        with pytest.raises(SystemExit):
            get_auth_provider(settings, allow_aws_gateway=False)

    def test_allowed_constructs(self):
        from iam_validator.mcp.auth import AwsGatewayAuthProvider

        settings = ServerSettings(auth="aws-gateway")
        provider = get_auth_provider(settings, allow_aws_gateway=True)
        assert isinstance(provider, AwsGatewayAuthProvider)

    def test_build_server_refuses_without_allow_aws_gateway(self):
        from iam_validator.mcp.build import build_server

        settings = ServerSettings(auth="aws-gateway")
        with pytest.raises(SystemExit):
            build_server(settings)

    def test_create_app_refuses_without_allow_aws_gateway(self):
        from iam_validator.mcp.asgi import create_app

        settings = ServerSettings(auth="aws-gateway")
        with pytest.raises(SystemExit):
            create_app(settings)


class TestScopeToTagMapping:
    def test_canonical_mapping(self):
        from iam_validator.mcp.auth import SCOPE_TO_TAG

        assert SCOPE_TO_TAG == {
            "iam:validate": "validate",
            "iam:query": "query",
            "iam:analyze": "analyze",
            "iam:config": "orgconfig",
        }
