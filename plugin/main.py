import os
from functools import partial
from typing import Callable, MutableMapping

import httpx
from armasec.token_payload import TokenPayload
from armasec.exceptions import ArmasecError
from armasec.pluggable import hookimpl
from armasec.utilities import log_error
from cachetools import TTLCache
from starlette import status
from starlette.requests import Request


class ArmasecSubscriptionsError(ArmasecError):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Error while checking subscriptions."


class ArmasecSubscriptionsNotSubscribed(ArmasecError):
    status_code = status.HTTP_402_PAYMENT_REQUIRED
    detail = "User is not subscribed."


sub_check_url = os.getenv("ARMASEC_SUB_URL")
allow_reads: bool = True if os.getenv("ARMASEC_SUB_ALLOW_READS") else False
allow_deletes: bool = True if os.getenv("ARMASEC_SUB_ALLOW_DELETES") else False

request_cache: MutableMapping[str, bool] = TTLCache(
    int(os.getenv("ARMASEC_SUB_CACHE_MAX", 1024**2)),  # Default is ~1 million records
    int(os.getenv("ARMASEC_SUB_CACHE_TTL", 15 * 60)),  # Default is 15 min
)


@hookimpl
def armasec_plugin_check(
    request: Request,
    token_payload: TokenPayload,
    debug_logger: Callable[..., None],
):
    debug_logger("Applying subscription check in armasec-submissions plugin")

    debug_logger(
        f"""
        Armasec Subscriptions configuration:
          - {sub_check_url=}
          - {allow_reads=}
          - {allow_deletes=}
        """
    )

    if not sub_check_url:
        debug_logger("Skipping subscription check because env var ARMSEC_SUB_URL is not set")
        return

    if request.method == "GET" and allow_reads:
        debug_logger("Skipping subscription check because env var ARMSEC_SUB_ALLOW_READS is set")
        return

    if request.method == "DELETE" and allow_deletes:
        debug_logger("Skipping subscription check because env var ARMSEC_SUB_ALLOW_DELETES is set")
        return

    token = ArmasecSubscriptionsError.enforce_defined(
        token_payload.original_token,
        "Token payload is missing original token",
    )

    debug_logger(f"Checking in request cache for subscription result for {token[:32]}...")
    cached_result = request_cache.get(token)
    if cached_result:
        debug_logger("User has cached active subscription")
        return
    debug_logger("No cached results found")

    debug_logger(f"Issuing request to sub url {sub_check_url} with token {token[:32]}...")
    with ArmasecSubscriptionsError.handle_errors(
        f"Could not fetch response from {sub_check_url}!",
        do_except=partial(log_error, debug_logger),
    ):
        response = httpx.get(sub_check_url, headers=dict(Authorization=f"Bearer {token}"))

    debug_logger(f"Received response from {sub_check_url}: {response.text}")

    if response.status_code == status.HTTP_200_OK:
        debug_logger("User is subscribed. Caching result.")
        request_cache[token] = True
    else:
        raise ArmasecSubscriptionsNotSubscribed("User is not subscribed!")
