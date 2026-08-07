import email.utils
import math
import time
import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse
from urllib3.util.retry import Retry
import malwoverview.modules.configvars as cv

DEFAULT_TIMEOUT = (15, 180)
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 1
SLOW_SERVICE_RETRIES = 5
SLOW_SERVICE_BACKOFF = 2
RATE_LIMIT_MAX_RETRIES = 3
RATE_LIMIT_MAX_WAIT = 300
RATE_LIMIT_DEFAULT_WAIT = 60

NETWORK_FAILURE_HINTS = (
    ('CERTIFICATE_VERIFY_FAILED',
     "The certificate presented for this host could not be verified. That is usually a "
     "TLS-intercepting proxy; on a network where you did not expect one, treat it as a finding "
     "rather than a glitch."),
    ('WRONG_VERSION_NUMBER',
     "The port answered but not with TLS, which usually means a proxy or a captive portal is "
     "answering in place of the service."),
    ('UNEXPECTED_EOF',
     "The host accepted the TLS connection and then closed it without answering. That is a fault "
     "on the service side, not on yours, and retrying now is unlikely to help."),
    ('SSLV3_ALERT_HANDSHAKE_FAILURE',
     "The host refused the TLS handshake."),
)


def network_failure_message(error, service=None):
    host = ''
    request = getattr(error, 'request', None)
    if request is not None:
        try:
            host = urlparse(request.url).hostname or ''
        except Exception:
            host = ''

    if not host and service:
        host = service
    where = " to %s" % host if host else ''
    message = ("\nThe request%s failed (%s). The service may be unreachable, slow or temporarily "
               "unavailable; check your connection or proxy and retry.\n"
               % (where, type(error).__name__))

    hint = network_failure_hint(error)
    if hint:
        message = message + hint + "\n"
    return message


def failure_message(error, service=None):
    if isinstance(error, requests.exceptions.RequestException):
        return network_failure_message(error, service)
    return "\n%s\n" % error


def network_failure_hint(error):
    try:
        text = str(error).upper()
    except Exception:
        return ''
    for marker, hint in NETWORK_FAILURE_HINTS:
        if marker in text:
            return hint
    return ''


def _retry_after_seconds(response):
    retry_after = response.headers.get('Retry-After')
    if not retry_after:
        return RATE_LIMIT_DEFAULT_WAIT

    retry_after = str(retry_after).strip()

    try:
        return max(int(retry_after), 0)
    except ValueError:
        pass

    parsed = email.utils.parsedate_tz(retry_after)
    if parsed is None:
        return RATE_LIMIT_DEFAULT_WAIT

    try:
        target = email.utils.mktime_tz(parsed)
    except (TypeError, ValueError, OverflowError):
        return RATE_LIMIT_DEFAULT_WAIT

    return max(int(math.ceil(target - time.time())), 0)


def _replayable(kwargs):
    if kwargs.get('files'):
        return False

    body = kwargs.get('data')
    if body is None or isinstance(body, (str, bytes, bytearray, dict, list, tuple)):
        return True

    return not (hasattr(body, 'read') or hasattr(body, '__iter__'))


class _DefaultTimeoutSession(requests.Session):
    def request(self, *args, **kwargs):
        if kwargs.get('timeout') is None:
            kwargs['timeout'] = DEFAULT_TIMEOUT

        attempts = 0

        while True:
            response = super().request(*args, **kwargs)

            if response.status_code != 429 or attempts >= RATE_LIMIT_MAX_RETRIES:
                return response

            wait_time = _retry_after_seconds(response)
            if wait_time > RATE_LIMIT_MAX_WAIT or not _replayable(kwargs):
                return response

            attempts += 1

            if cv.verbosity >= 0:
                print(f"\nRate limited (429). Waiting {wait_time}s before retrying...")

            response.close()
            time.sleep(wait_time)


def create_session(headers=None, retries=DEFAULT_RETRIES, backoff=DEFAULT_BACKOFF,
                   raise_on_status=True):
    session = _DefaultTimeoutSession()

    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"],
        raise_on_status=raise_on_status,
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    if cv.proxy:
        session.proxies = {"http": cv.proxy, "https": cv.proxy}

    if headers:
        session.headers.update(headers)

    return session
