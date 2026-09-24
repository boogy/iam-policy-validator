"""Auth provider factory, selected by ``ServerSettings.auth``.

``get_auth_provider()`` is the only place a FastMCP ``AuthProvider`` is constructed.
Everything it needs beyond ``ServerSettings`` (token material, JWT/IdP config) is read
from ``IAM_VALIDATOR_MCP_AUTH_*`` environment variables or a file path they name --
never from a CLI flag, which would land in shell history, ``ps`` output, and
container-inspect output.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

from fastmcp.server.auth import AccessToken, AuthProvider
from fastmcp.server.auth.auth import AuthContextMiddleware
from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.authentication import AuthCredentials, AuthenticationBackend
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection

from iam_validator.mcp.settings import ServerSettings

# The only ServerSettings.auth value gated by allow_aws_gateway; shared with awslambda.py
# so the two never drift into comparing against different spellings.
AWS_GATEWAY_AUTH_PROVIDER = "aws-gateway"

# Canonical scope -> ComponentSpec.tag mapping, attached per-tag via restrict_tag(tag,
# scopes=[...]) elsewhere. No `generation`/`iam:generate` entry -- that surface is gone.
SCOPE_TO_TAG: dict[str, str] = {
    "iam:validate": "validate",
    "iam:query": "query",
    "iam:analyze": "analyze",
    "iam:config": "orgconfig",
}

# Tags deliberately left ungated; test_scope_gating.py requires every tag to appear here or in SCOPE_TO_TAG.
SCOPE_FREE_TAGS: frozenset[str] = frozenset({"fix"})

_ENV_PREFIX = "IAM_VALIDATOR_MCP_AUTH_"


def _fail(message: str) -> NoReturn:
    print(f"iam-validator-mcp: {message}", file=sys.stderr)
    raise SystemExit(1)


def _env(name: str) -> str | None:
    value = os.environ.get(_ENV_PREFIX + name)
    return value if value else None


def _require_env(name: str) -> str:
    value = _env(name)
    if not value:
        _fail(f"--auth requires {_ENV_PREFIX}{name}")
    return value


def _required_scopes() -> list[str] | None:
    raw = _env("REQUIRED_SCOPES")
    return [s.strip() for s in raw.split(",") if s.strip()] if raw else None


def _load_static_tokens() -> dict[str, dict[str, Any]]:
    file_value = _env("TOKEN_FILE")
    inline_value = _env("TOKENS")
    if file_value and inline_value:
        _fail(f"{_ENV_PREFIX}TOKEN_FILE and {_ENV_PREFIX}TOKENS are mutually exclusive; set only one")
    if not file_value and not inline_value:
        _fail(
            f"--auth token requires {_ENV_PREFIX}TOKEN_FILE (a file path) or "
            f"{_ENV_PREFIX}TOKENS (inline JSON) -- never a command-line flag"
        )

    if file_value:
        try:
            raw = Path(file_value).read_text()
        except OSError as exc:
            _fail(f"cannot read {_ENV_PREFIX}TOKEN_FILE={file_value!r}: {exc}")
    else:
        raw = inline_value  # type: ignore[assignment]

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        _fail(f"--auth token source is not valid JSON: {exc}")
    if not isinstance(data, dict) or not data:
        _fail("--auth token source must be a non-empty JSON object mapping token -> metadata")
    for index, (token, meta) in enumerate(data.items()):
        if not isinstance(meta, dict) or "client_id" not in meta:
            # sha256, not the token itself -- this message is written to stderr/logs.
            fingerprint = hashlib.sha256(token.encode()).hexdigest()[:8]
            _fail(f"token entry #{index} (fingerprint {fingerprint}) is missing required 'client_id'")
    return data


def _build_token_provider() -> AuthProvider:
    return StaticTokenVerifier(tokens=_load_static_tokens(), required_scopes=_required_scopes())


def _build_jwt_provider() -> AuthProvider:
    jwks_uri = _env("JWT_JWKS_URI")
    public_key = _env("JWT_PUBLIC_KEY")
    if bool(jwks_uri) == bool(public_key):
        _fail(f"--auth jwt requires exactly one of {_ENV_PREFIX}JWT_JWKS_URI or {_ENV_PREFIX}JWT_PUBLIC_KEY")
    issuer = _require_env("JWT_ISSUER")
    audience = _require_env("JWT_AUDIENCE")
    try:
        return JWTVerifier(
            jwks_uri=jwks_uri,
            public_key=public_key,
            issuer=issuer,
            audience=audience,
            algorithm=_env("JWT_ALGORITHM"),
            required_scopes=_required_scopes(),
        )
    except ValueError as exc:
        _fail(f"--auth jwt configuration is invalid: {exc}")


def _base_url(settings: ServerSettings) -> str:
    return _env("BASE_URL") or f"http://{settings.host}:{settings.port}"


def _build_azure_provider(settings: ServerSettings) -> AuthProvider:
    from fastmcp.server.auth.providers.azure import AzureProvider

    # AzureProvider rejects a required_scopes made up only of OIDC scopes, so there is no safe default.
    scopes = _required_scopes()
    if not scopes:
        _fail(
            f"--auth azure requires {_ENV_PREFIX}REQUIRED_SCOPES naming at least one "
            "non-OIDC API scope exposed by your Azure app registration (e.g. 'api://<app-id>/access')"
        )
    return AzureProvider(
        client_id=_require_env("AZURE_CLIENT_ID"),
        client_secret=_env("AZURE_CLIENT_SECRET"),
        tenant_id=_require_env("AZURE_TENANT_ID"),
        required_scopes=scopes,
        base_url=_base_url(settings),
    )


def _build_google_provider(settings: ServerSettings) -> AuthProvider:
    from fastmcp.server.auth.providers.google import GoogleProvider

    return GoogleProvider(
        client_id=_require_env("GOOGLE_CLIENT_ID"),
        client_secret=_env("GOOGLE_CLIENT_SECRET"),
        base_url=_base_url(settings),
        required_scopes=_required_scopes(),
    )


def _build_github_provider(settings: ServerSettings) -> AuthProvider:
    from fastmcp.server.auth.providers.github import GitHubProvider

    return GitHubProvider(
        client_id=_require_env("GITHUB_CLIENT_ID"),
        client_secret=_require_env("GITHUB_CLIENT_SECRET"),
        base_url=_base_url(settings),
        required_scopes=_required_scopes(),
    )


def _build_keycloak_provider(settings: ServerSettings) -> AuthProvider:
    from fastmcp.server.auth.providers.keycloak import KeycloakAuthProvider

    return KeycloakAuthProvider(
        realm_url=_require_env("KEYCLOAK_REALM_URL"),
        base_url=_base_url(settings),
        required_scopes=_required_scopes(),
        audience=_env("KEYCLOAK_AUDIENCE"),
    )


def _build_auth0_provider(settings: ServerSettings) -> AuthProvider:
    from fastmcp.server.auth.providers.auth0 import Auth0Provider

    return Auth0Provider(
        config_url=_require_env("AUTH0_CONFIG_URL"),
        client_id=_require_env("AUTH0_CLIENT_ID"),
        client_secret=_require_env("AUTH0_CLIENT_SECRET"),
        audience=_require_env("AUTH0_AUDIENCE"),
        base_url=_base_url(settings),
        required_scopes=_required_scopes(),
    )


def _build_workos_provider(settings: ServerSettings) -> AuthProvider:
    from fastmcp.server.auth.providers.workos import AuthKitProvider

    return AuthKitProvider(
        authkit_domain=_require_env("WORKOS_AUTHKIT_DOMAIN"),
        base_url=_base_url(settings),
        required_scopes=_required_scopes(),
    )


class _AwsGatewayBackend(AuthenticationBackend):
    """Reads already-verified claims from the Lambda adapter's ``requestContext``.

    Never reads a header: auth terminates upstream of this process (a Function URL
    with ``AuthType: AWS_IAM``, or an API Gateway JWT authorizer), so a header on the
    inbound request is attacker-controlled and must never be trusted as identity.
    """

    def __init__(self, scope_claim: str) -> None:
        self._scope_claim = scope_claim

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, AuthenticatedUser] | None:
        event = conn.scope.get("aws.event")
        if not isinstance(event, dict):
            return None
        request_context = event.get("requestContext")
        if not isinstance(request_context, dict):
            return None
        authorizer = request_context.get("authorizer")
        if not isinstance(authorizer, dict):
            return None

        jwt_claims = authorizer.get("jwt", {}).get("claims") if isinstance(authorizer.get("jwt"), dict) else None
        if isinstance(jwt_claims, dict):
            subject = str(jwt_claims.get("sub", ""))
            raw_scopes = jwt_claims.get(self._scope_claim, "")
            scopes = raw_scopes if isinstance(raw_scopes, list) else str(raw_scopes).replace(",", " ").split()
            claims = dict(jwt_claims)
        elif isinstance(authorizer.get("iam"), dict):
            iam = authorizer["iam"]
            subject = str(iam.get("userArn") or iam.get("userId") or "")
            # AWS_IAM carries no OAuth scopes; scoped tools stay hidden for this caller.
            scopes = []
            claims = dict(iam)
        else:
            return None

        access_token = AccessToken(
            token=AWS_GATEWAY_AUTH_PROVIDER,  # noqa: S106 -- not a secret, a fixed sentinel marking the auth source
            client_id=subject or AWS_GATEWAY_AUTH_PROVIDER,
            scopes=list(scopes),
            subject=subject or None,
            claims=claims,
        )
        return AuthCredentials(list(scopes)), AuthenticatedUser(access_token)


class AwsGatewayAuthProvider(AuthProvider):
    """Trusts claims the Lambda adapter already verified; never verifies a bearer token itself.

    Only ``get_auth_provider(..., allow_aws_gateway=True)`` -- called exclusively from
    ``iam_validator.mcp.awslambda`` -- may construct this; see that gate below.
    """

    def __init__(self, *, scope_claim: str) -> None:
        super().__init__()
        self._scope_claim = scope_claim

    async def verify_token(self, token: str) -> AccessToken | None:
        # Never called: get_middleware() below replaces the bearer-token backend
        # entirely, so no code path here ever inspects a header-borne token.
        return None

    def get_middleware(self) -> list[Middleware]:
        return [
            Middleware(AuthenticationMiddleware, backend=_AwsGatewayBackend(self._scope_claim)),
            Middleware(AuthContextMiddleware),
        ]


def _build_aws_gateway_provider() -> AuthProvider:
    return AwsGatewayAuthProvider(scope_claim=_env("AWS_GATEWAY_SCOPE_CLAIM") or "scope")


# Registered here, not spread across tool code, so adding a new IdP is one entry.
_IDP_PROVIDERS: dict[str, Callable[[ServerSettings], AuthProvider]] = {
    "azure": _build_azure_provider,
    "google": _build_google_provider,
    "github": _build_github_provider,
    "keycloak": _build_keycloak_provider,
    "auth0": _build_auth0_provider,
    "workos": _build_workos_provider,
}


def get_auth_provider(
    settings: ServerSettings,
    *,
    token_cli_flag: str | None = None,
    allow_aws_gateway: bool = False,
) -> AuthProvider | None:
    """Build the ``AuthProvider`` for ``settings.auth``, or ``None`` for ``"none"``.

    ``token_cli_flag`` must always be ``None``; it exists only so a CLI wiring
    mistake that threads a token through a flag is caught here rather than
    silently accepted (see module docstring). ``allow_aws_gateway`` must stay
    ``False`` for every caller except ``iam_validator.mcp.awslambda`` -- it is
    what keeps ``--auth aws-gateway`` from ever binding to a plain uvicorn app.
    """
    if token_cli_flag is not None:
        _fail("a token must never be passed via a command-line flag; use a token file or env var")

    if settings.auth == "none":
        if settings.mode == "hosted" and not settings.auth_explicitly_set:
            _fail(
                "mode='hosted' requires an authenticated --auth provider; pass "
                "--auth none explicitly to opt into an unauthenticated hosted server"
            )
        return None

    if settings.auth == AWS_GATEWAY_AUTH_PROVIDER:
        if not allow_aws_gateway:
            _fail(
                "--auth aws-gateway is only valid behind the Lambda adapter "
                "(iam_validator.mcp.awslambda); it must never be selected for uvicorn/stdio serving"
            )
        return _build_aws_gateway_provider()

    if settings.auth == "token":
        return _build_token_provider()

    if settings.auth == "jwt":
        return _build_jwt_provider()

    builder = _IDP_PROVIDERS.get(settings.auth)
    if builder is None:
        _fail(f"unknown --auth provider {settings.auth!r}")
    try:
        return builder(settings)
    except ValueError as exc:
        _fail(f"--auth {settings.auth} configuration is invalid: {exc}")


__all__ = ["get_auth_provider", "SCOPE_TO_TAG", "SCOPE_FREE_TAGS", "AwsGatewayAuthProvider"]
