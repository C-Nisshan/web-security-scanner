"""
/backend/scanner/auth_manager.py — Authentication Manager
=========================================
Centralises all authentication logic for the Aegis scanner.

Supported auth modes
--------------------
  cookie  — raw "Name=Value; Name2=Value2" cookie string
  bearer  — Authorization: Bearer <token>
  basic   — HTTP Basic (username / password header)
  dvwa    — DVWA form login with automatic CSRF extraction
  form    — Generic form login with hidden-input CSRF handling

Layer : Infrastructure Layer

Usage
-----
    # Cookie / session auth
    auth = AuthManager()
    auth.apply_cookie_auth("PHPSESSID=abc123; security=low")
    session = auth.get_session()

    # DVWA auto-login
    auth = AuthManager()
    ok = auth.login_dvwa("http://dvwa:80", "admin", "password")
    session = auth.get_session()

    # Generic Bearer token
    auth = AuthManager()
    auth.apply_bearer_auth("eyJhbGci...")
    session = auth.get_session()
"""

import logging
import requests
import urllib3
from typing import Dict, Optional

from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("auth_manager")

DEFAULT_USER_AGENT = "AegisSecurity/1.0 Web Application Assessment"


# ─────────────────────────────────────────────────────────────
# AuthManager
# ─────────────────────────────────────────────────────────────

class AuthManager:
    """
    Manages authenticated HTTP sessions for the Aegis scanner pipeline.

    All auth methods return ``self`` for fluent chaining, e.g.:
        session = AuthManager().apply_cookie_auth("...").get_session()
    """

    def __init__(self, user_agent: str = DEFAULT_USER_AGENT):
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})
        self._session.verify = False          # many test targets use self-signed certs
        self._authenticated = False
        self._auth_type: Optional[str] = None

    # ── Cookie auth ───────────────────────────────────────────

    def apply_cookie_auth(self, cookie_string: str) -> "AuthManager":
        """
        Parse and inject a raw HTTP cookie string into the session.

        Parameters
        ----------
        cookie_string : "PHPSESSID=abc123; security=low; foo=bar"
        """
        if not cookie_string or not cookie_string.strip():
            logger.warning("[AuthManager] Empty cookie string — skipped")
            return self

        for part in cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                self._session.cookies.set(name.strip(), value.strip())
                logger.debug("[AuthManager] Cookie set: %s", name.strip())

        self._authenticated = True
        self._auth_type = "cookie"
        logger.info("[AuthManager] Cookie auth applied (%d cookies)",
                    len(self._session.cookies))
        return self

    # ── Bearer token auth ─────────────────────────────────────

    def apply_bearer_auth(self, token: str) -> "AuthManager":
        """
        Inject an Authorization: Bearer header.

        Parameters
        ----------
        token : raw JWT or API token (without the 'Bearer ' prefix)
        """
        if not token or not token.strip():
            logger.warning("[AuthManager] Empty bearer token — skipped")
            return self

        self._session.headers.update(
            {"Authorization": f"Bearer {token.strip()}"}
        )
        self._authenticated = True
        self._auth_type = "bearer"
        logger.info("[AuthManager] Bearer token applied")
        return self

    # ── HTTP Basic auth ───────────────────────────────────────

    def apply_basic_auth(self, username: str, password: str) -> "AuthManager":
        """Apply RFC 7617 HTTP Basic Authentication."""
        self._session.auth = (username, password)
        self._authenticated = True
        self._auth_type = "basic"
        logger.info("[AuthManager] Basic auth applied (user=%s)", username)
        return self

    # ── DVWA auto-login ───────────────────────────────────────

    def login_dvwa(
        self,
        base_url: str,
        username: str = "admin",
        password: str = "password",
        security_level: str = "low",
    ) -> bool:
        """
        Authenticate against DVWA, handling its CSRF user_token.

        Steps
        -----
        1. GET /login.php  → extract user_token
        2. POST credentials + token  → verify success
        3. POST /security.php        → set security level

        Parameters
        ----------
        base_url       : DVWA base URL, e.g. "http://dvwa:80"
        username       : default "admin"
        password       : default "password"
        security_level : "low" | "medium" | "high" | "impossible"

        Returns
        -------
        True on success, False on failure.
        """
        base_url   = base_url.rstrip("/")
        login_url  = f"{base_url}/login.php"
        sec_url    = f"{base_url}/security.php"

        try:
            # ── Step 1: fetch login page ──────────────────────
            resp = self._session.get(login_url, timeout=12)
            resp.raise_for_status()

            soup        = BeautifulSoup(resp.text, "html.parser")
            token_tag   = soup.find("input", {"name": "user_token"})
            user_token  = token_tag["value"] if token_tag else ""

            if not user_token:
                logger.warning("[AuthManager] DVWA: user_token not found — "
                               "attempting login without it")

            # ── Step 2: POST credentials ──────────────────────
            login_resp = self._session.post(
                login_url,
                data={
                    "username"  : username,
                    "password"  : password,
                    "Login"     : "Login",
                    "user_token": user_token,
                },
                timeout=12,
                allow_redirects=True,
            )

            # ── Step 3: confirm success ───────────────────────
            body = login_resp.text.lower()
            if "logout" in body or "welcome" in body or "dvwa security" in body:
                logger.info("[AuthManager] DVWA login OK (user=%s)", username)

                # ── Step 4: set security level ─────────────────
                try:
                    self._session.post(
                        sec_url,
                        data={"security": security_level,
                              "seclev_submit": "Submit"},
                        timeout=10,
                    )
                    logger.info("[AuthManager] DVWA security level → %s",
                                security_level)
                except Exception:
                    logger.warning("[AuthManager] Could not set DVWA security level")

                self._authenticated = True
                self._auth_type = "dvwa_form"
                return True

            logger.error("[AuthManager] DVWA login FAILED for user='%s'", username)
            return False

        except Exception as exc:
            logger.exception("[AuthManager] DVWA login error: %s", exc)
            return False

    # ── Generic form login ────────────────────────────────────

    def login_form(
        self,
        login_url: str,
        credentials: Dict[str, str],
        success_indicator: str = "",
    ) -> bool:
        """
        Generic form-based login with automatic hidden-input capture.

        Fetches the login page first to collect CSRF tokens / hidden
        fields, merges them with ``credentials``, then POSTs.

        Parameters
        ----------
        login_url         : URL of the login endpoint
        credentials       : e.g. {"username": "admin", "password": "pass"}
        success_indicator : substring expected in the response body
                            when login succeeds (case-insensitive).
                            Leave blank to use heuristic URL-change check.

        Returns
        -------
        True if login appeared to succeed, False otherwise.
        """
        try:
            get_resp = self._session.get(login_url, timeout=12)
            soup     = BeautifulSoup(get_resp.text, "html.parser")

            form_data = dict(credentials)
            for hidden in soup.find_all("input", {"type": "hidden"}):
                name = hidden.get("name", "")
                val  = hidden.get("value", "")
                if name and name not in form_data:
                    form_data[name] = val

            resp = self._session.post(
                login_url, data=form_data,
                timeout=12, allow_redirects=True,
            )

            if success_indicator:
                success = success_indicator.lower() in resp.text.lower()
            else:
                success = resp.url != login_url

            if success:
                self._authenticated = True
                self._auth_type = "form"
                logger.info("[AuthManager] Form login succeeded at %s", login_url)
            else:
                logger.warning("[AuthManager] Form login may have failed at %s",
                               login_url)

            return success

        except Exception as exc:
            logger.exception("[AuthManager] Form login error: %s", exc)
            return False

    # ── Accessors ─────────────────────────────────────────────

    def get_session(self) -> requests.Session:
        """Return the configured (and possibly authenticated) session."""
        return self._session

    def get_cookies(self) -> Dict[str, str]:
        """Return all current session cookies as a plain dict."""
        return dict(self._session.cookies)

    def get_headers(self) -> Dict[str, str]:
        """Return the current session headers."""
        return dict(self._session.headers)

    @property
    def is_authenticated(self) -> bool:
        """True if any auth method has been applied successfully."""
        return self._authenticated

    @property
    def auth_type(self) -> Optional[str]:
        """Name of the auth method applied, or None."""
        return self._auth_type

    def __repr__(self) -> str:
        return (
            f"AuthManager(authenticated={self._authenticated}, "
            f"auth_type={self._auth_type!r})"
        )


# ─────────────────────────────────────────────────────────────
# Factory helper
# ─────────────────────────────────────────────────────────────

def build_auth_manager(auth_config: Optional[Dict]) -> Optional[AuthManager]:
    """
    Construct and configure an AuthManager from the API request auth block.

    Supported ``auth_config`` shapes
    ---------------------------------
    { "type": "cookie",  "value": "PHPSESSID=abc; security=low" }
    { "type": "bearer",  "value": "eyJhbGci..." }
    { "type": "basic",   "username": "admin",   "password": "pass" }
    { "type": "dvwa",    "base_url": "http://dvwa:80",
                         "username": "admin",   "password": "password",
                         "security_level": "low" }
    { "type": "form",    "login_url": "http://...",
                         "credentials": {"user": "admin", "pass": "x"},
                         "success_indicator": "dashboard" }

    Returns None when auth_config is absent or empty.
    """
    if not auth_config:
        return None

    auth_type = (auth_config.get("type") or "").lower().strip()
    manager   = AuthManager()

    if auth_type == "cookie":
        manager.apply_cookie_auth(auth_config.get("value", ""))

    elif auth_type == "bearer":
        manager.apply_bearer_auth(auth_config.get("value", ""))

    elif auth_type == "basic":
        manager.apply_basic_auth(
            auth_config.get("username", ""),
            auth_config.get("password", ""),
        )

    elif auth_type == "dvwa":
        ok = manager.login_dvwa(
            base_url       = auth_config.get("base_url", ""),
            username       = auth_config.get("username", "admin"),
            password       = auth_config.get("password", "password"),
            security_level = auth_config.get("security_level", "low"),
        )
        if not ok:
            logger.error("[build_auth_manager] DVWA login failed")
            return None

    elif auth_type == "form":
        ok = manager.login_form(
            login_url         = auth_config.get("login_url", ""),
            credentials       = auth_config.get("credentials", {}),
            success_indicator = auth_config.get("success_indicator", ""),
        )
        if not ok:
            logger.error("[build_auth_manager] Form login failed")
            return None

    else:
        logger.warning("[build_auth_manager] Unknown auth type '%s'", auth_type)
        return None

    return manager