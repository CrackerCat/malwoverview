import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, strip_json_escapes, report_header, bullet
from malwoverview.utils.session import create_session, SLOW_SERVICE_RETRIES, SLOW_SERVICE_BACKOFF
from malwoverview.utils.output import collector, is_text_output
from malwoverview.utils.sanitize import sanitize_domain
from urllib.parse import quote
from datetime import datetime


REPORT_WIDTH = 100
COL_DNSNAME = 64
COL_WILDCARD = 10
SUBDOMAIN_TABLE_WIDTH = COL_DNSNAME + COL_WILDCARD

COL_CERTID = 13
COL_ISSUER = 46
COL_COMMONNAME = 42
COL_NOTBEFORE = 21
COL_NOTAFTER = 21
CERT_TABLE_WIDTH = COL_CERTID + COL_ISSUER + COL_COMMONNAME + COL_NOTBEFORE + COL_NOTAFTER

DEFAULT_SUBDOMAIN_LIMIT = 200
DEFAULT_CERT_LIMIT = 50
MAX_LIMIT = 5000

_TIMESTAMP_FORMATS = (
    '%Y-%m-%dT%H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S.%f',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d',
)


def truncate(value, maxlen):
    text = str(value)
    if maxlen < 4 or len(text) <= maxlen:
        return text[:maxlen] if maxlen >= 0 else text
    return text[:maxlen - 3] + '...'


def normalize_limit(limit, default):
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return default
    if value <= 0:
        return default
    return min(value, MAX_LIMIT)


def parse_timestamp(value):
    text = str(value if value is not None else '').strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1]
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except (TypeError, ValueError):
            continue
    return None


def cert_sort_key(cert):
    parsed = parse_timestamp(cert.get('not_before'))
    if parsed is None:
        return (0, datetime.min)
    return (1, parsed)


class CrtShExtractor:
    urlcrtsh = 'https://crt.sh/'

    def _print_report_header(self, title, width=None):
        print()
        print(report_header(title, REPORT_WIDTH if width is None else width))

    def _print_fields(self, fields):
        colsize = max(len(field) for field in fields.keys()) + 3
        for field, value in fields.items():
            print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(colsize) + mycolors.reset + str(value))

    def _raw_query(self, query):
        url = f"{CrtShExtractor.urlcrtsh}?q={quote(query, safe='')}&output=json"

        if is_text_output():
            print(bullet("Querying crt.sh. This frequently takes minutes, and failed "
                         "responses are retried.", SUBDOMAIN_TABLE_WIDTH,
                         mycolors.foreground.info(cv.bkg)), flush=True)

        try:
            session = create_session({'Accept': 'application/json'},
                                     retries=SLOW_SERVICE_RETRIES,
                                     backoff=SLOW_SERVICE_BACKOFF,
                                     raise_on_status=False)
            response = session.get(url)
        except Exception as e:
            return [], f"Could not reach crt.sh: {str(e)}. Certificate Transparency queries are slow; retry in a few minutes."

        status = getattr(response, 'status_code', 0)

        if status == 429:
            return [], "crt.sh rate limit exceeded (HTTP 429). Wait a few minutes before querying again."
        if status in (502, 503, 504):
            return [], f"crt.sh is temporarily unavailable (HTTP {status}) and did not recover after retries. Retry in a few minutes."
        if status != 200:
            return [], f"crt.sh returned HTTP {status} for this query. Confirm https://crt.sh is reachable and retry; the service is frequently slow or briefly unavailable."

        body = response.content or b''
        if not body.strip():
            return [], "crt.sh returned an empty response. The query most likely timed out server-side. Retry, or query a narrower domain."

        try:
            data = strip_json_escapes(response.json())
        except Exception:
            return [], "crt.sh returned a non-JSON response (usually an HTML error or maintenance page). Retry in a few minutes."

        if isinstance(data, dict):
            message = str(data.get('message') or data.get('error') or data)
            return [], f"crt.sh returned an error object instead of certificates: {truncate(message, 200)}"
        if not isinstance(data, list):
            return [], "crt.sh returned an unexpected response format (a JSON array of certificates was expected)."

        return [cert for cert in data if isinstance(cert, dict)], None

    def crtsh_subdomains(self, domain, limit=DEFAULT_SUBDOMAIN_LIMIT):
        cleandomain, error = sanitize_domain(str(domain))

        if is_text_output():
            self._print_report_header("CRT.SH SUBDOMAIN REPORT", SUBDOMAIN_TABLE_WIDTH)

        if error:
            if is_text_output():
                print()
                print(bullet(error, SUBDOMAIN_TABLE_WIDTH,
                             mycolors.foreground.error(cv.bkg)))
            return False

        maxrows = normalize_limit(limit, DEFAULT_SUBDOMAIN_LIMIT)

        certs, error = self._raw_query('%.' + cleandomain)
        if error:
            if is_text_output():
                print()
                print(bullet(error, SUBDOMAIN_TABLE_WIDTH,
                             mycolors.foreground.error(cv.bkg)))
            return False

        if not certs:
            if is_text_output():
                print()
                print(bullet(f"No certificates for {cleandomain} were found in the "
                             "Certificate Transparency logs.", SUBDOMAIN_TABLE_WIDTH,
                             mycolors.foreground.error(cv.bkg)))
            return False

        names = set()
        outofscope = set()
        suffix = '.' + cleandomain

        for cert in certs:
            candidates = str(cert.get('name_value') or '').splitlines()
            candidates.append(str(cert.get('common_name') or ''))

            for candidate in candidates:
                entry = candidate.strip().strip('.').lower()
                if not entry:
                    continue
                if entry == cleandomain or entry.endswith(suffix):
                    names.add(entry)
                else:
                    outofscope.add(entry)

        allnames = sorted(names)
        total = len(allnames)
        shown = allnames[:maxrows]

        if is_text_output():
            fields = {
                'Domain': cleandomain,
                'Query': '%.' + cleandomain,
                'Certificates': str(len(certs)),
                'Distinct DNS Names': str(total),
                'Showing': str(len(shown)),
            }
            if outofscope:
                fields['Out Of Scope'] = f"{len(outofscope)} name(s) skipped"
            print()
            self._print_fields(fields)
            print()
            print(
                mycolors.foreground.info(cv.bkg)
                + "DNS Name".ljust(COL_DNSNAME)
                + "Wildcard".center(COL_WILDCARD)
                + mycolors.reset
            )
            print(SUBDOMAIN_TABLE_WIDTH * '-')

        for name in shown:
            wildcard = 'YES' if name.startswith('*.') else 'NO'

            collector.add({
                'domain': cleandomain,
                'dns_name': name,
                'wildcard': wildcard,
            })

            if is_text_output():
                print(
                    mycolors.foreground.success(cv.bkg)
                    + truncate(name, COL_DNSNAME - 2).ljust(COL_DNSNAME)
                    + mycolors.foreground.info(cv.bkg)
                    + wildcard.center(COL_WILDCARD)
                    + mycolors.reset
                )

        if is_text_output():
            print()
            if total > len(shown):
                print(bullet(f"Found {total} distinct name(s), showing {len(shown)}. "
                             f"Raise the limit (max {MAX_LIMIT}) to see more.",
                             SUBDOMAIN_TABLE_WIDTH))
            else:
                print(bullet(f"Found {total} distinct name(s), showing all {len(shown)}.",
                             SUBDOMAIN_TABLE_WIDTH))

        return True

    def crtsh_certificates(self, domain, limit=DEFAULT_CERT_LIMIT):
        cleandomain, error = sanitize_domain(str(domain))

        if is_text_output():
            self._print_report_header("CRT.SH CERTIFICATE REPORT", CERT_TABLE_WIDTH)

        if error:
            if is_text_output():
                print()
                print(bullet(error, CERT_TABLE_WIDTH,
                             mycolors.foreground.error(cv.bkg)))
            return False

        maxrows = normalize_limit(limit, DEFAULT_CERT_LIMIT)

        certs, error = self._raw_query(cleandomain)
        if error:
            if is_text_output():
                print()
                print(bullet(error, CERT_TABLE_WIDTH,
                             mycolors.foreground.error(cv.bkg)))
            return False

        if not certs:
            if is_text_output():
                print()
                print(bullet(f"No certificates for {cleandomain} were found in the "
                             "Certificate Transparency logs.", CERT_TABLE_WIDTH,
                             mycolors.foreground.error(cv.bkg)))
            return False

        certs = sorted(certs, key=cert_sort_key, reverse=True)
        total = len(certs)
        shown = certs[:maxrows]

        if is_text_output():
            print()
            self._print_fields({
                'Domain': cleandomain,
                'Certificates': str(total),
                'Showing': str(len(shown)),
            })
            print()
            print(
                mycolors.foreground.info(cv.bkg)
                + "Cert ID".ljust(COL_CERTID)
                + "Issuer".ljust(COL_ISSUER)
                + "Common Name".ljust(COL_COMMONNAME)
                + "Not Before".ljust(COL_NOTBEFORE)
                + "Not After"
                + mycolors.reset
            )
            print(CERT_TABLE_WIDTH * '-')

        for cert in shown:
            certid = str(cert.get('id', 'N/A'))
            issuer = str(cert.get('issuer_name') or 'N/A')
            commonname = str(cert.get('common_name') or 'N/A')
            notbefore = str(cert.get('not_before') or 'N/A')
            notafter = str(cert.get('not_after') or 'N/A')

            collector.add({
                'domain': cleandomain,
                'certificate_id': certid,
                'issuer_name': issuer,
                'common_name': commonname,
                'not_before': notbefore,
                'not_after': notafter,
                'serial_number': str(cert.get('serial_number') or 'N/A'),
                'entry_timestamp': str(cert.get('entry_timestamp') or 'N/A'),
            })

            if is_text_output():
                print(
                    mycolors.foreground.success(cv.bkg)
                    + truncate(certid, COL_CERTID - 2).ljust(COL_CERTID)
                    + mycolors.reset
                    + truncate(issuer, COL_ISSUER - 2).ljust(COL_ISSUER)
                    + mycolors.foreground.success(cv.bkg)
                    + truncate(commonname, COL_COMMONNAME - 2).ljust(COL_COMMONNAME)
                    + mycolors.reset
                    + truncate(notbefore, COL_NOTBEFORE - 2).ljust(COL_NOTBEFORE)
                    + truncate(notafter, COL_NOTAFTER - 2)
                    + mycolors.reset
                )

        if is_text_output():
            print()
            if total > len(shown):
                print(bullet(f"Found {total} certificate(s), showing {len(shown)}. "
                             f"Raise the limit (max {MAX_LIMIT}) to see more.",
                             CERT_TABLE_WIDTH))
            else:
                print(bullet(f"Found {total} certificate(s), showing all {len(shown)}.",
                             CERT_TABLE_WIDTH))

        return True
