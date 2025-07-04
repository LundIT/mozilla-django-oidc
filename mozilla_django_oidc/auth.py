import base64
import hashlib
import json
import logging
import inspect
import requests

from django.contrib.auth import get_user_model, BACKEND_SESSION_KEY
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.urls import reverse
from django.utils.encoding import force_bytes, smart_bytes, smart_str
from django.utils.module_loading import import_string
from josepy.b64 import b64decode
from josepy.jwk import JWK
from josepy.jws import JWS, Header
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError

from mozilla_django_oidc.utils import absolutify, import_from_settings

LOGGER = logging.getLogger(__name__)


def default_username_algo(email, claims=None):
    """Generate username for the Django user."""
    username = base64.urlsafe_b64encode(
        hashlib.sha1(force_bytes(email)).digest()
    ).rstrip(b"=")
    return smart_str(username)


class OIDCAuthenticationBackend(ModelBackend):
    """Override Django's authentication to store refresh tokens when offline_access is requested."""

    def __init__(self, *args, **kwargs):
        self.OIDC_OP_TOKEN_ENDPOINT = self.get_settings("OIDC_OP_TOKEN_ENDPOINT")
        self.OIDC_OP_USER_ENDPOINT = self.get_settings("OIDC_OP_USER_ENDPOINT")
        self.OIDC_OP_JWKS_ENDPOINT = self.get_settings("OIDC_OP_JWKS_ENDPOINT", None)
        self.OIDC_RP_CLIENT_ID = self.get_settings("OIDC_RP_CLIENT_ID")
        self.OIDC_RP_CLIENT_SECRET = self.get_settings("OIDC_RP_CLIENT_SECRET")
        self.OIDC_RP_SIGN_ALGO = self.get_settings("OIDC_RP_SIGN_ALGO", "HS256")
        self.OIDC_RP_IDP_SIGN_KEY = self.get_settings("OIDC_RP_IDP_SIGN_KEY", None)

        if (
            self.OIDC_RP_SIGN_ALGO.startswith("RS")
            or self.OIDC_RP_SIGN_ALGO.startswith("ES")
        ) and (
            self.OIDC_RP_IDP_SIGN_KEY is None
            and self.OIDC_OP_JWKS_ENDPOINT is None
        ):
            msg = "{} alg requires OIDC_RP_IDP_SIGN_KEY or OIDC_OP_JWKS_ENDPOINT."
            raise ImproperlyConfigured(msg.format(self.OIDC_RP_SIGN_ALGO))

        self.UserModel = get_user_model()

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    def describe_user_by_claims(self, claims):
        return "email {}".format(claims.get("email"))

    def filter_users_by_claims(self, claims):
        email = claims.get("email")
        if not email:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(email__iexact=email)

    def verify_claims(self, claims):
        scopes = self.get_settings("OIDC_RP_SCOPES", "openid email").split()
        if "email" in scopes:
            return "email" in claims
        LOGGER.warning(
            "Custom OIDC_RP_SCOPES defined. Override `verify_claims` for custom checks."
        )
        return True

    def create_user(self, claims):
        email = claims.get("email")
        username = self.get_username(claims)
        return self.UserModel.objects.create_user(username, email=email)

    def get_username(self, claims):
        username_algo = self.get_settings("OIDC_USERNAME_ALGO", None)
        if username_algo:
            if isinstance(username_algo, str):
                username_algo = import_string(username_algo)
            args = inspect.getfullargspec(username_algo).args
            if len(args) == 1:
                return username_algo(claims.get("email"))
            else:
                return username_algo(claims.get("email"), claims)
        return default_username_algo(claims.get("email"), claims)

    def update_user(self, user, claims):
        return user

    def _verify_jws(self, payload, key):
        jws = JWS.from_compact(payload)
        try:
            alg = jws.signature.combined.alg.name
        except KeyError:
            raise SuspiciousOperation("No alg value in JWS header")
        if alg != self.OIDC_RP_SIGN_ALGO:
            raise SuspiciousOperation(
                f"Provider alg {alg!r} does not match OIDC_RP_SIGN_ALGO"
            )
        jwk = JWK.load(smart_bytes(key)) if isinstance(key, str) else JWK.from_json(key)
        if not jws.verify(jwk):
            raise SuspiciousOperation("JWS token verification failed.")
        return jws.payload

    def retrieve_matching_jwk(self, token):
        resp = requests.get(
            self.OIDC_OP_JWKS_ENDPOINT,
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", None),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        resp.raise_for_status()
        jwks = resp.json()
        jws = JWS.from_compact(token)
        header = Header.json_loads(jws.signature.protected)
        for jwk in jwks["keys"]:
            if import_from_settings("OIDC_VERIFY_KID", True) and jwk.get("kid") != smart_str(header.kid):
                continue
            if jwk.get("alg") and jwk["alg"] != smart_str(header.alg):
                continue
            return jwk
        raise SuspiciousOperation("Could not find a valid JWKS.")

    def get_payload_data(self, token, key):
        if self.get_settings("OIDC_ALLOW_UNSECURED_JWT", False):
            hdr, pl, _ = token.split(b".")
            hdr_json = json.loads(smart_str(b64decode(hdr)))
            if hdr_json.get("alg") == "none":
                return b64decode(pl)
        return self._verify_jws(token, key)

    def verify_token(self, token, **kwargs):
        nonce = kwargs.get("nonce")
        token = force_bytes(token)
        if self.OIDC_RP_SIGN_ALGO.startswith(("RS", "ES")):
            key = self.OIDC_RP_IDP_SIGN_KEY or self.retrieve_matching_jwk(token)
        else:
            key = self.OIDC_RP_CLIENT_SECRET
        payload_data = self.get_payload_data(token, key)
        payload = json.loads(payload_data.decode("utf-8"))
        if self.get_settings("OIDC_USE_NONCE", True) and nonce != payload.get("nonce"):
            raise SuspiciousOperation("JWT Nonce verification failed.")
        return payload

    def get_token(self, payload):
        auth = None
        if self.get_settings("OIDC_TOKEN_USE_BASIC_AUTH", False):
            auth = HTTPBasicAuth(payload["client_id"], payload["client_secret"])
            del payload["client_secret"]
        resp = requests.post(
            self.OIDC_OP_TOKEN_ENDPOINT,
            data=payload,
            auth=auth,
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", None),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        if resp.status_code != 200:
            raise HTTPError(
                f"Get Token Error (status: {resp.status_code}, body: {resp.text})",
                response=resp
            )
        return resp.json()

    def get_userinfo(self, access_token, id_token, payload):
        resp = requests.get(
            self.OIDC_OP_USER_ENDPOINT,
            headers={"Authorization": f"Bearer {access_token}"},
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", None),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        resp.raise_for_status()
        return resp.json()

    def authenticate(self, request, **kwargs):
        self.request = request
        if not request:
            return None

        state = request.GET.get("state")
        code = request.GET.get("code")
        nonce = kwargs.pop("nonce", None)
        code_verifier = kwargs.pop("code_verifier", None)
        if not code or not state:
            return None

        callback = self.get_settings("OIDC_AUTHENTICATION_CALLBACK_URL", "oidc_authentication_callback")
        token_payload = {
            "client_id": self.OIDC_RP_CLIENT_ID,
            "client_secret": self.OIDC_RP_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": absolutify(request, reverse(callback)),
        }
        if code_verifier:
            token_payload["code_verifier"] = code_verifier

        token_info = self.get_token(token_payload)
        id_token = token_info.get("id_token")
        access_token = token_info.get("access_token")
        refresh_token = token_info.get("refresh_token")

        # log all three tokens
        LOGGER.debug("Received tokens: id_token=%s, access_token=%s, refresh_token=%s",
                     id_token, access_token, refresh_token)

        payload = self.verify_token(id_token, nonce=nonce)
        if not payload:
            return None

        # Store tokens: id, access, and—if offline_access was requested—the refresh token.
        self.store_tokens(access_token, id_token, refresh_token)

        try:
            return self.get_or_create_user(access_token, id_token, payload)
        except SuspiciousOperation as exc:
            LOGGER.warning("failed to get or create user: %s", exc)
            return None

    def store_tokens(self, access_token, id_token, refresh_token=None):
        """Store OIDC tokens in the session."""
        session = self.request.session
        if self.get_settings("OIDC_STORE_ACCESS_TOKEN", False):
            session["oidc_access_token"] = access_token
        if self.get_settings("OIDC_STORE_ID_TOKEN", False):
            session["oidc_id_token"] = id_token

        # New: if offline_access was in requested scopes, save the refresh_token by default
        scopes = self.get_settings("OIDC_RP_SCOPES", "").split()
        if "offline_access" in scopes and refresh_token:
            session["oidc_refresh_token"] = refresh_token

    def get_or_create_user(self, access_token, id_token, payload):
        user_info = self.get_userinfo(access_token, id_token, payload)
        if not self.verify_claims(user_info):
            raise SuspiciousOperation("Claims verification failed")
        users = self.filter_users_by_claims(user_info)
        if len(users) == 1:
            return self.update_user(users[0], user_info)
        if len(users) > 1:
            raise SuspiciousOperation("Multiple users returned")
        if self.get_settings("OIDC_CREATE_USER", True):
            return self.create_user(user_info)
        LOGGER.debug(
            "Login failed: no user found and OIDC_CREATE_USER=False for %s",
            self.describe_user_by_claims(user_info),
        )
        return None

    def get_user(self, user_id):
        try:
            return self.UserModel.objects.get(pk=user_id)
        except self.UserModel.DoesNotExist:
            return None
