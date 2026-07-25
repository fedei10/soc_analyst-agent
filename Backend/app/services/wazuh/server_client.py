"""Read-only client for the Wazuh Server API on port 55000."""

import json
import time
from threading import Lock
from typing import Any

import httpx

from app.config import settings
from app.core.observability.wazuh import observe_wazuh_call
from app.services.wazuh.exceptions import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhPermissionError,
    WazuhTimeoutError,
    WazuhValidationError,
)

TOKEN_LIFETIME_SECONDS = 800


def _validate_wazuh_envelope(
    response: httpx.Response,
    *,
    allow_partial: bool = False,
) -> None:
    """Reject Wazuh failures carried inside an HTTP-success response."""
    if "application/json" not in response.headers.get("content-type", "").lower():
        return

    try:
        payload = response.json()
    except ValueError:
        return
    if not isinstance(payload, dict):
        return

    data = payload.get("data")
    data = data if isinstance(data, dict) else {}
    failed_items = data.get("failed_items")
    failed_items = failed_items if isinstance(failed_items, list) else []
    total_failed = data.get("total_failed_items", len(failed_items))
    try:
        total_failed = int(total_failed)
    except (TypeError, ValueError):
        total_failed = len(failed_items)

    wazuh_error = payload.get("error", 0)
    if wazuh_error in (None, 0) and total_failed == 0:
        return
    if allow_partial and wazuh_error == 2:
        return

    message = payload.get("message") or "Wazuh operation failed."
    raise WazuhAPIError(
        f"{message} Wazuh error={wazuh_error}, failed_items={total_failed}.",
        response.status_code,
    )


class _AuthenticatedWazuhTransport:
    """Shared authenticated transport; public clients expose only safe operations."""

    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        verify: bool | str,
        timeout: httpx.Timeout | float | None = None,
        component: str = "server",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.component = component
        self._username = username
        self._password = password
        self._client = httpx.Client(
            base_url=self.base_url,
            verify=verify,
            timeout=timeout or httpx.Timeout(
                connect=5.0,
                read=float(settings.WAZUH_TIMEOUT),
                write=10.0,
                pool=5.0,
            ),
            transport=httpx.HTTPTransport(retries=3, verify=verify),
        )
        self._token: str | None = None
        self._token_expires_at = 0.0

    def authenticate(self) -> str:
        with observe_wazuh_call(
            operation="authenticate",
            component=self.component,
        ):
            try:
                response = self._client.post(
                    "/security/user/authenticate",
                    params={"raw": "true"},
                    auth=(self._username, self._password),
                )
            except httpx.HTTPError as exc:
                raise WazuhAPIError(
                    f"Cannot reach Wazuh API at {self.base_url}: "
                    f"{exc.__class__.__name__}"
                ) from exc

            if response.status_code in {401, 403}:
                raise WazuhAuthError(
                    "Wazuh authentication failed: check the configured "
                    "credentials."
                )
            self._raise_for_http_status(
                response,
                "POST",
                "/security/user/authenticate",
            )

            token = response.text.strip().strip('"')
            if not token:
                raise WazuhAuthError("Wazuh API returned an empty token.")
            self._token = token
            self._token_expires_at = time.time() + TOKEN_LIFETIME_SECONDS
            return token

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        allow_partial: bool = False,
        timeout_seconds: float | None = None,
    ) -> httpx.Response:
        method = method.upper()
        path = "/" + path.lstrip("/")
        resource = path.strip("/").split("/", 1)[0] or "root"
        with observe_wazuh_call(
            operation=f"{method.lower()}_{resource}",
            component=self.component,
        ):
            token = self._get_token()
            response = self._send(
                method,
                path,
                params,
                json,
                token,
                timeout_seconds,
            )
            if response.status_code == 401:
                response = self._send(
                    method,
                    path,
                    params,
                    json,
                    self._get_token(force_refresh=True),
                    timeout_seconds,
                )
            self._raise_for_http_status(response, method, path)
            _validate_wazuh_envelope(
                response,
                allow_partial=allow_partial,
            )
            return response

    def close(self) -> None:
        self._client.close()

    def _get_token(self, force_refresh: bool = False) -> str:
        if force_refresh or not self._token or time.time() >= self._token_expires_at:
            return self.authenticate()
        return self._token

    def _send(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        json: dict[str, Any] | None,
        token: str,
        timeout_seconds: float | None = None,
    ) -> httpx.Response:
        try:
            request_kwargs: dict[str, Any] = {
                "headers": {"Authorization": f"Bearer {token}"},
                "params": params,
                "json": json,
            }
            if timeout_seconds is not None:
                request_kwargs["timeout"] = timeout_seconds
            return self._client.request(method, path, **request_kwargs)
        except httpx.TimeoutException as exc:
            raise WazuhTimeoutError(
                f"Wazuh API {method} {path} exceeded its configured timeout."
            ) from exc
        except httpx.HTTPError as exc:
            raise WazuhAPIError(
                f"Wazuh API {method} {path} transport error: {exc.__class__.__name__}"
            ) from exc

    @staticmethod
    def _raise_for_http_status(response: httpx.Response, method: str, path: str) -> None:
        if not response.is_error:
            return
        detail = ""
        try:
            payload = response.json()
            if isinstance(payload, dict):
                detail = str(payload.get("detail") or payload.get("title") or payload.get("message") or "")
        except ValueError:
            pass
        message = (
            f"Wazuh API {method} {path} failed with HTTP {response.status_code}: "
            f"{detail or 'no detail'}"
        )
        if response.status_code == 401:
            raise WazuhAuthError(message)
        if response.status_code == 403:
            raise WazuhPermissionError(message)
        raise WazuhAPIError(message, response.status_code)


class WazuhServerClient:
    """Generic authenticated GET access for deterministic application services."""

    def __init__(
        self,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> None:
        verify_ssl = settings.WAZUH_VERIFY_SSL if verify_ssl is None else verify_ssl
        verify: bool | str = (settings.WAZUH_CA_CERT or True) if verify_ssl else False
        self._transport = _AuthenticatedWazuhTransport(
            base_url=base_url or settings.WAZUH_BASE_URL,
            username=username or settings.WAZUH_USERNAME,
            password=password or settings.WAZUH_PASSWORD.get_secret_value(),
            verify=verify,
            timeout=timeout,
        )
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._cache_lock = Lock()

    def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        allow_partial: bool = False,
    ) -> dict[str, Any]:
        clean = self._validate_params(params)
        cache_key = f"{path}:{json.dumps(clean, sort_keys=True, default=str)}:{allow_partial}"
        now = time.monotonic()
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached and cached[0] > now:
                return cached[1]
        payload = self._transport.request(
            "GET", path, params=clean or None, allow_partial=allow_partial
        ).json()
        with self._cache_lock:
            if len(self._cache) >= 256:
                oldest = min(self._cache, key=lambda key: self._cache[key][0])
                self._cache.pop(oldest)
            self._cache[cache_key] = (now + 30.0, payload)
        return payload

    def get_raw(self, path: str, params: dict[str, Any] | None = None) -> str:
        clean = self._validate_params(params)
        return self._transport.request("GET", path, params=clean or None).text

    def authenticate(self) -> str:
        return self._transport.authenticate()

    def close(self) -> None:
        self._cache.clear()
        self._transport.close()

    @staticmethod
    def _validate_params(params: dict[str, Any] | None) -> dict[str, Any]:
        clean = {key: value for key, value in (params or {}).items() if value is not None}
        limit = clean.get("limit")
        if limit is None:
            return clean
        try:
            limit = int(limit)
        except (TypeError, ValueError) as exc:
            raise WazuhValidationError(f"limit must be an integer, got {limit!r}.") from exc
        if not 1 <= limit <= settings.WAZUH_MAX_LIMIT:
            raise WazuhValidationError(
                f"limit must be between 1 and WAZUH_MAX_LIMIT={settings.WAZUH_MAX_LIMIT}, got {limit}."
            )
        clean["limit"] = limit
        return clean
