import logging
import time
from urllib.error import HTTPError

import requests
from re import Pattern as re_Pattern
from urllib.parse import quote, urlencode

from django.contrib.auth import BACKEND_SESSION_KEY
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import (
    absolutify,
    add_state_and_verifier_and_nonce_to_session,
    generate_code_challenge,
    import_from_settings,
)

LOGGER = logging.getLogger(__name__)

class InvalidRefreshTokenError(Exception):
    """Raised when the OP tells us the refresh_token is no longer valid."""
    pass

class SessionRefresh(MiddlewareMixin):
    """Refreshes the session with the OIDC RP after expiry seconds.

    First tries a refresh_token grant; if that fails or no refresh_token is
    present, falls back to a silent `prompt=none` re-auth.
    """

    def __init__(self, get_response):
        super().__init__(get_response)
        # URLs & endpoints
        self.OIDC_EXEMPT_URLS = self.get_settings("OIDC_EXEMPT_URLS", [])
        self.OIDC_OP_AUTHORIZATION_ENDPOINT = self.get_settings("OIDC_OP_AUTHORIZATION_ENDPOINT")
        self.OIDC_OP_TOKEN_ENDPOINT = self.get_settings("OIDC_OP_TOKEN_ENDPOINT")
        # RP credentials
        self.OIDC_RP_CLIENT_ID = self.get_settings("OIDC_RP_CLIENT_ID")
        self.OIDC_RP_CLIENT_SECRET = self.get_settings("OIDC_RP_CLIENT_SECRET", None)
        # State & nonce
        self.OIDC_STATE_SIZE = self.get_settings("OIDC_STATE_SIZE", 32)
        self.OIDC_USE_NONCE = self.get_settings("OIDC_USE_NONCE", True)
        self.OIDC_NONCE_SIZE = self.get_settings("OIDC_NONCE_SIZE", 32)
        # Callback & scope
        self.OIDC_AUTHENTICATION_CALLBACK_URL = self.get_settings(
            "OIDC_AUTHENTICATION_CALLBACK_URL", "oidc_authentication_callback"
        )
        self.OIDC_RP_SCOPES = self.get_settings("OIDC_RP_SCOPES", "openid email")
        # PKCE settings
        self.OIDC_USE_PKCE = self.get_settings("OIDC_USE_PKCE", False)
        self.OIDC_PKCE_CODE_VERIFIER_SIZE = self.get_settings("OIDC_PKCE_CODE_VERIFIER_SIZE", 64)
        self.OIDC_PKCE_CODE_CHALLENGE_METHOD = self.get_settings("OIDC_PKCE_CODE_CHALLENGE_METHOD", "S256")

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    @cached_property
    def exempt_urls(self):
        exempt = [
            url if url.startswith("/") else reverse(url)
            for url in self.OIDC_EXEMPT_URLS
            if not isinstance(url, re_Pattern)
        ]
        exempt += [
            "oidc_authentication_init",
            "oidc_authentication_callback",
            "oidc_logout",
        ]
        return set(exempt)

    @cached_property
    def exempt_url_patterns(self):
        return {p for p in self.OIDC_EXEMPT_URLS if isinstance(p, re_Pattern)}

    def is_refreshable_url(self, request):
        backend_path = request.session.get(BACKEND_SESSION_KEY)
        is_oidc = True
        if backend_path:
            backend = import_string(backend_path)
            is_oidc = issubclass(backend, OIDCAuthenticationBackend)

        return (
            request.method == "GET"
            and request.user.is_authenticated
            and is_oidc
            and request.path not in self.exempt_urls
            and not any(p.match(request.path) for p in self.exempt_url_patterns)
        )

    def process_request(self, request):
        print("SessionRefresh: process_request called")
        if not self.is_refreshable_url(request):
            LOGGER.debug("request is not refreshable")
            return

        now = time.time()
        expiration = request.session.get("oidc_id_token_expiration", 0)

        if expiration > now:
            LOGGER.debug("id token still valid (%s > %s)", expiration, now)
            return

        LOGGER.debug("id token expired or missing; attempting token refresh")

        # 1) Try the refresh_token grant
        refresh_token = request.session.get("oidc_refresh_token")
        if refresh_token:
            try:
                tokens = self._refresh_with_refresh_token(refresh_token)
                self._update_session_tokens(request, tokens, now)
                LOGGER.debug("successfully refreshed tokens via refresh_token")
                return
            except InvalidRefreshTokenError:
                # Kick the user fully out if their refresh_token is no good
                LOGGER.warning("Refresh token invalid – sending user to logout flow")
                return HttpResponseRedirect(reverse("oidc_logout"))
            except Exception:
                # Some other network/HTTP error – fall back to silent auth
                LOGGER.exception("refresh_token grant failed; falling back to silent auth")

        # 2) Fallback: silent re‐auth via prompt=none
        return self._perform_silent_auth(request)

    def _refresh_with_refresh_token(self, refresh_token):
        """Exchange the refresh_token at the OP's token endpoint."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.OIDC_RP_CLIENT_ID,
        }
        if self.OIDC_RP_CLIENT_SECRET:
            data["client_secret"] = self.OIDC_RP_CLIENT_SECRET

        resp = requests.post(self.OIDC_OP_TOKEN_ENDPOINT, data=data)
        try:
            resp.raise_for_status()
        except HTTPError as e:
            # If the OP tells us the refresh_token is invalid, escalate
            try:
                error = resp.json().get("error")
            except ValueError:
                error = None

            if resp.status_code == 400 and error == "invalid_grant":
                # means the refresh_token was revoked or expired
                raise InvalidRefreshTokenError("Refresh token invalid or expired") from e
            # any other HTTPError, re-raise and let caller decide
            raise

        return resp.json()

    def _update_session_tokens(self, request, tokens, now):
        """Save new id_token, access_token, (rotated) refresh_token, and expiration."""
        request.session["oidc_id_token"] = tokens["id_token"]
        request.session["oidc_access_token"] = tokens.get("access_token")
        if "refresh_token" in tokens:
            request.session["oidc_refresh_token"] = tokens["refresh_token"]
            print("oidc_refresh_token", tokens["refresh_token"])
        expires_in = tokens.get("expires_in")
        if expires_in is not None:
            request.session["oidc_id_token_expiration"] = now + int(expires_in)

    def _perform_silent_auth(self, request):
        """Redirect the user silently (`prompt=none`) to re‐authenticate."""
        LOGGER.debug("performing silent auth with prompt=none")
        state = get_random_string(self.OIDC_STATE_SIZE)
        params = {
            "response_type": "code",
            "client_id": self.OIDC_RP_CLIENT_ID,
            "redirect_uri": absolutify(request, reverse(self.OIDC_AUTHENTICATION_CALLBACK_URL)),
            "state": state,
            "scope": self.OIDC_RP_SCOPES,
            "prompt": "none",
        }
        # include any extra params from settings
        params.update(self.get_settings("OIDC_AUTH_REQUEST_EXTRA_PARAMS", {}))

        # nonce for replay protection
        if self.OIDC_USE_NONCE:
            params["nonce"] = get_random_string(self.OIDC_NONCE_SIZE)

        # PKCE support
        code_verifier = None
        if self.OIDC_USE_PKCE:
            if not (43 <= self.OIDC_PKCE_CODE_VERIFIER_SIZE <= 128):
                raise ValueError("code_verifier_length must be between 43 and 128")
            code_verifier = get_random_string(self.OIDC_PKCE_CODE_VERIFIER_SIZE)
            code_challenge = generate_code_challenge(code_verifier, self.OIDC_PKCE_CODE_CHALLENGE_METHOD)
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = self.OIDC_PKCE_CODE_CHALLENGE_METHOD

        # stash state, verifier, nonce
        add_state_and_verifier_and_nonce_to_session(request, state, params, code_verifier)
        request.session["oidc_login_next"] = request.get_full_path()

        # build redirect
        query = urlencode(params, quote_via=quote)
        redirect_url = f"{self.OIDC_OP_AUTHORIZATION_ENDPOINT}?{query}"

        # handle AJAX specially
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            response = JsonResponse({"refresh_url": redirect_url}, status=403)
            response["refresh_url"] = redirect_url
            return response

        return HttpResponseRedirect(redirect_url)
