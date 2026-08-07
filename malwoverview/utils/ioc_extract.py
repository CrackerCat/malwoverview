import re
import os
import html
import ipaddress
from urllib.parse import urlparse, urljoin
import socket
import requests
from requests.adapters import HTTPAdapter

from malwoverview.utils.colors import (
    mycolors, printr, bullet, pad, wrap_field, strip_terminal_escapes,
)
import malwoverview.modules.configvars as cv
from malwoverview.utils.output import collector, is_text_output
from malwoverview.utils.session import create_session, network_failure_hint
from malwoverview.utils.sanitize import defang
from malwoverview.utils.tlds import has_valid_tld

_CANDIDATE_TOKEN_RE = re.compile(r'[A-Za-z0-9._%+@-]+')
_MAX_TOKEN_LEN = 512
_TOKENIZED_PATTERNS = ('domains', 'emails')

REPORT_WIDTH = 100
FIELD_WIDTH = 16

_COMMENT_OPEN = '<!--'
_COMMENT_CLOSE = '-->'
_BLOCK_TAGS = ('script', 'style', 'svg', 'noscript')
_BLOCK_OPEN_RE = re.compile(r'<(%s)\b' % '|'.join(_BLOCK_TAGS), re.I)
_BLOCK_CLOSE_RE = {tag: re.compile(r'</%s\s*>' % tag, re.I) for tag in _BLOCK_TAGS}
_LINK_ATTR_RE = re.compile(
    r'\b(?:href|src|data-src|action)\s*=\s*["\']([^"\']{1,2048})["\']', re.I)
_TAG_RE = re.compile(r'<[^<>]{0,4096}>')
_HTML_HINT_RE = re.compile(r'<(?:html|head|body|div|script|meta|a\s)', re.I)
_ABSOLUTE_URL_RE = re.compile(r'\s*(?:https?:)?//', re.I)

_MULTI_PART_SUFFIXES = frozenset((
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
    'co.kr', 'or.kr', 'go.kr', 'co.za', 'org.za', 'gov.za',
    'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve', 'com.ec',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz',
    'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.my', 'com.ph',
    'co.id', 'co.th', 'com.vn', 'co.il', 'com.pl', 'com.ua', 'com.ru',
    'com.sa', 'com.eg', 'com.ng', 'com.pk', 'com.bd',
))

BOILERPLATE_HOSTS = frozenset((
    'w3.org', 'schema.org', 'creativecommons.org', 'gmpg.org',
    'googletagmanager.com', 'google-analytics.com', 'doubleclick.net',
    'googleadservices.com', 'googlesyndication.com', 'adservice.google.com',
    'adobedtm.com', 'demdex.net', 'omtrdc.net', 'newrelic.com',
    'js-agent.newrelic.com', 'nr-data.net', 'bc0a.com', 'datagrail.io',
    'onetrust.com', 'cookielaw.org', 'trustarc.com', 'hotjar.com',
    'segment.com', 'segment.io', 'optimizely.com', 'demandbase.com',
    'marketo.net', 'marketo.com', 'pardot.com', 'munchkin.marketo.net',
    '6sc.co', 'clarity.ms', 'quantserve.com', 'scorecardresearch.com',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'gstatic.com',
    'bootstrapcdn.com', 'jsdelivr.net', 'cdnjs.cloudflare.com',
    'jquery.com', 'unpkg.com', 'typekit.net', 'use.typekit.net',
    'fontawesome.com', 'gravatar.com', 'parastorage.com', 'wp.com',
    'facebook.com', 'fb.com', 'twitter.com', 'x.com', 'linkedin.com',
    'instagram.com', 'youtube.com', 'youtu.be', 'pinterest.com',
    'tiktok.com', 'reddit.com', 'whatsapp.com', 'threads.net',
))


def _registrable(host):
    if not host:
        return ''
    host = host.strip().strip('.').lower()
    labels = host.split('.')
    if len(labels) < 2:
        return host
    if len(labels) >= 3 and '.'.join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def _is_boilerplate(host):
    host = (host or '').strip().strip('.').lower()
    if not host:
        return False
    if host in BOILERPLATE_HOSTS or _registrable(host) in BOILERPLATE_HOSTS:
        return True
    return any(host.endswith('.' + entry) for entry in BOILERPLATE_HOSTS)


def _cut_comments(markup):
    kept = []
    position = 0
    while True:
        start = markup.find(_COMMENT_OPEN, position)
        if start < 0:
            kept.append(markup[position:])
            return ''.join(kept)
        kept.append(markup[position:start])
        kept.append(' ')
        end = markup.find(_COMMENT_CLOSE, start + len(_COMMENT_OPEN))
        if end < 0:
            return ''.join(kept)
        position = end + len(_COMMENT_CLOSE)


def _cut_blocks(markup):
    kept = []
    position = 0
    while True:
        opening = _BLOCK_OPEN_RE.search(markup, position)
        if opening is None:
            kept.append(markup[position:])
            return ''.join(kept)
        kept.append(markup[position:opening.start()])
        kept.append(' ')
        closing = _BLOCK_CLOSE_RE[opening.group(1).lower()].search(markup, opening.end())
        if closing is None:
            return ''.join(kept)
        position = closing.end()


def html_to_text(markup):
    stripped = _cut_blocks(_cut_comments(markup))
    links = [value for value in _LINK_ATTR_RE.findall(stripped)
             if _ABSOLUTE_URL_RE.match(value)]
    return html.unescape(_TAG_RE.sub(' ', stripped) + '\n' + '\n'.join(links))


def looks_like_html(text):
    return bool(_HTML_HINT_RE.search(text[:8192]))


class _SNIPinnedAdapter(HTTPAdapter):
    def __init__(self, hostname, **kwargs):
        self._sni_hostname = hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['server_hostname'] = self._sni_hostname
        super().init_poolmanager(*args, **kwargs)


class IOCExtractor:
    def __init__(self):
        self.patterns = {
            'ipv4': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
            ),
            'ipv6': re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
                r'|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
                r'|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
            ),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'urls': re.compile(
                r'(?:https?|hxxps?|ftp)://[^\s<>\"\'\x00-\x20\x7f-\x9f]+'
            ),
            'domains': re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
                r'+(?:[a-zA-Z]{2,})\b'
            ),
            'emails': re.compile(
                r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            ),
            'cves': re.compile(r'CVE-\d{4}-\d{4,}'),
        }
        self.suppressed = {}

    def refang(self, text):
        text = text.replace('hxxp', 'http')
        text = text.replace('hxxps', 'https')
        text = text.replace('[.]', '.')
        text = text.replace('[:]', ':')
        return text

    def extract_from_text(self, text, source=None, is_html=None):
        self.suppressed = {}
        self.html_stripped = False
        if cv.ioc_filter:
            if is_html is None:
                is_html = looks_like_html(text)
            if is_html:
                text = html_to_text(text)
                self.html_stripped = True
        text = self.refang(text)
        results = {}
        tokens = None
        for name, pattern in self.patterns.items():
            if name in _TOKENIZED_PATTERNS:
                if tokens is None:
                    tokens = [
                        token for token in _CANDIDATE_TOKEN_RE.findall(text)
                        if '.' in token and len(token) <= _MAX_TOKEN_LEN
                    ]
                matches = []
                for token in tokens:
                    matches.extend(pattern.findall(token))
            else:
                matches = pattern.findall(text)
            results[name] = [value for value in
                             {strip_terminal_escapes(match) for match in matches} if value]
        if cv.ioc_filter:
            results = self._suppress_noise(results, source)
        return results

    def _suppress_noise(self, results, source):
        own = ''
        if source and self.is_url(source):
            own = _registrable(urlparse(source).hostname or '')
        self.source_site = own

        def drop(host):
            host = (host or '').lower()
            if not host:
                return True
            if own and (_registrable(host) == own):
                return True
            return _is_boilerplate(host)

        kept_domains = []
        dropped = 0
        for domain in results.get('domains', []):
            if not has_valid_tld(domain) or drop(domain):
                dropped += 1
                continue
            kept_domains.append(domain)
        if dropped:
            self.suppressed['domains'] = dropped
        results['domains'] = kept_domains

        kept_urls = []
        dropped = 0
        for url in results.get('urls', []):
            try:
                host = urlparse(url).hostname or ''
            except ValueError:
                host = ''
            if drop(host):
                dropped += 1
                continue
            kept_urls.append(url)
        if dropped:
            self.suppressed['urls'] = dropped
        results['urls'] = kept_urls

        return results

    @staticmethod
    def is_url(value):
        return bool(re.match(r'^https?://', value, re.IGNORECASE))

    @staticmethod
    def _is_ip_blocked(ip):
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return (
            ip.is_private or ip.is_loopback or ip.is_reserved
            or ip.is_link_local or ip.is_multicast or ip.is_unspecified
        )

    @staticmethod
    def _validate_url_target(url):
        if not isinstance(url, str) or not url:
            return False, "Invalid URL.", None, None
        for ch in url:
            if ch == '\\' or ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f:
                return False, "Invalid URL: contains backslash, whitespace, or control characters.", None, None
        try:
            prepared_url = requests.Request('GET', url).prepare().url
        except Exception:
            return False, "Invalid URL.", None, None
        parsed = urlparse(prepared_url)
        if parsed.scheme not in ('http', 'https'):
            return False, "Only http/https URLs are allowed.", None, None
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL: no hostname.", None, None
        if any(c in hostname for c in '\\/@ \t\r\n'):
            return False, "Invalid hostname.", None, None
        try:
            literal_ip = ipaddress.ip_address(hostname)
        except ValueError:
            literal_ip = None
        if literal_ip is not None:
            if IOCExtractor._is_ip_blocked(literal_ip):
                return False, f"URL resolves to private/reserved address ({hostname}). Blocked for security.", None, None
            return True, "", prepared_url, None
        try:
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            resolved = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError, ValueError):
            return False, f"Could not resolve hostname ({hostname}).", None, None
        addresses = []
        for _, _, _, _, addr in resolved:
            try:
                ip = ipaddress.ip_address(addr[0])
            except ValueError:
                return False, f"URL resolves to an unrecognized address ({addr[0]}). Blocked for security.", None, None
            if IOCExtractor._is_ip_blocked(ip):
                return False, f"URL resolves to private/reserved address ({addr[0]}). Blocked for security.", None, None
            addresses.append(addr[0])
        if not addresses:
            return False, f"Could not resolve hostname ({hostname}).", None, None
        pinned_ip = next((a for a in addresses if ':' not in a), addresses[0])
        return True, "", prepared_url, pinned_ip

    @staticmethod
    def _fetch_validated(session, safe_url, pinned_ip):
        if pinned_ip is None or cv.proxy:
            return session.get(safe_url, timeout=30, stream=True, allow_redirects=False)
        parsed = urlparse(safe_url)
        host_header = parsed.hostname if parsed.port is None else f"{parsed.hostname}:{parsed.port}"
        ip_netloc = f"[{pinned_ip}]" if ':' in pinned_ip else pinned_ip
        if parsed.port is not None:
            ip_netloc = f"{ip_netloc}:{parsed.port}"
        pinned_url = parsed._replace(netloc=ip_netloc).geturl()
        auth = (parsed.username or '', parsed.password or '') if parsed.username else None
        if parsed.scheme == 'https':
            retries = getattr(session.get_adapter('https://'), 'max_retries', None)
            adapter = (_SNIPinnedAdapter(parsed.hostname) if retries is None
                       else _SNIPinnedAdapter(parsed.hostname, max_retries=retries))
            session.mount('https://', adapter)
        return session.get(pinned_url, headers={'Host': host_header}, auth=auth,
                           timeout=30, stream=True, allow_redirects=False)

    def extract_from_url(self, url):
        MAX_SIZE = 10 * 1024 * 1024
        MAX_REDIRECTS = 5
        REDIRECT_STATUS = (301, 302, 303, 307, 308)
        pinned_ip = None

        try:
            session = create_session()

            # Follow redirects manually so every hop is re-validated against the
            # SSRF allowlist. Letting requests auto-follow would let a public
            # URL redirect to an internal/metadata address after the initial
            # check has already passed.
            current_url = url
            response = None
            for _ in range(MAX_REDIRECTS + 1):
                safe, reason, safe_url, pinned_ip = self._validate_url_target(current_url)
                if not safe:
                    print(
                        mycolors.foreground.error(cv.bkg)
                        + reason
                        + mycolors.reset
                    )
                    return {}

                response = self._fetch_validated(session, safe_url, pinned_ip)

                if response.status_code in REDIRECT_STATUS and 'Location' in response.headers:
                    location = response.headers.get('Location')
                    response.close()
                    if not location:
                        break
                    current_url = urljoin(safe_url, location)
                    continue
                break
            else:
                print(
                    mycolors.foreground.error(cv.bkg)
                    + f"Too many redirects (max {MAX_REDIRECTS})."
                    + mycolors.reset
                )
                return {}

            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '')
            content_length = response.headers.get('Content-Length', '')
            if content_length and int(content_length) > MAX_SIZE:
                print(
                    mycolors.foreground.error(cv.bkg)
                    + f"URL content too large ({content_length} bytes, max {MAX_SIZE})."
                    + mycolors.reset
                )
                return {}

            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                total += len(chunk)
                if total > MAX_SIZE:
                    print(
                        mycolors.foreground.error(cv.bkg)
                        + f"URL content exceeded {MAX_SIZE} bytes limit. Truncated."
                        + mycolors.reset
                    )
                    break
                chunks.append(chunk)

            raw = b''.join(chunks)

            if 'application/pdf' in content_type or url.lower().endswith('.pdf'):
                try:
                    from PyPDF2 import PdfReader
                    import io
                    reader = PdfReader(io.BytesIO(raw))
                    text = ''
                    for page in reader.pages:
                        page_text = page.extract_text()
                        if page_text:
                            text += page_text + '\n'
                    return self.extract_from_text(text, source=url, is_html=False)
                except ImportError:
                    print(
                        mycolors.foreground.error(cv.bkg)
                        + "PDF extraction requires PyPDF2: pip install malwoverview[pdf]"
                        + mycolors.reset
                    )
                    return {}

            text = raw.decode('utf-8', errors='ignore')
            is_html = 'html' in content_type.lower() or looks_like_html(text)
            return self.extract_from_text(text, source=url, is_html=is_html)

        except requests.exceptions.RequestException as e:
            self._print_fetch_failure(url, pinned_ip, e)
            return {}
        except Exception as e:
            print(
                mycolors.foreground.error(cv.bkg)
                + f"Error fetching URL: {str(e)}"
                + mycolors.reset
            )
            return {}

    @staticmethod
    def _print_fetch_failure(url, pinned_ip, error):
        try:
            hostname = urlparse(url).hostname or url
        except ValueError:
            hostname = url

        error_color = mycolors.foreground.error(cv.bkg)
        print(error_color
              + "\nCould not fetch %s (%s)." % (hostname, type(error).__name__)
              + mycolors.reset)

        hint = network_failure_hint(error)
        if hint:
            print(bullet(hint, REPORT_WIDTH, mycolors.foreground.neutral(cv.bkg)))
        else:
            print(bullet("The request failed before any content was read.",
                         REPORT_WIDTH, mycolors.foreground.neutral(cv.bkg)))

        if pinned_ip:
            print(bullet(
                "%s resolved to %s and that address was used for the request. If it is not the "
                "site's real server, your resolver may be returning a stale or parked record; "
                "check it against a public resolver before treating this as an outage."
                % (hostname, pinned_ip),
                REPORT_WIDTH, mycolors.foreground.neutral(cv.bkg)))

        if not hint:
            print(bullet(str(error)[:REPORT_WIDTH * 3], REPORT_WIDTH,
                         mycolors.foreground.neutral(cv.bkg)))

    def extract_from_file(self, filepath):
        ext = os.path.splitext(filepath)[1].lower()

        if ext == '.eml':
            import email
            from email import policy
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                msg = email.message_from_file(f, policy=policy.default)
            text = msg.get_body(preferencelist=('plain', 'html'))
            if text:
                text = text.get_content()
            else:
                text = str(msg)
            return self.extract_from_text(text)

        if ext == '.pdf':
            try:
                from PyPDF2 import PdfReader
            except ImportError:
                print(
                    mycolors.foreground.error(cv.bkg)
                    + "PDF extraction requires PyPDF2: pip install malwoverview[pdf]"
                    + mycolors.reset
                )
                return {}
            reader = PdfReader(filepath)
            text = ''
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + '\n'
            return self.extract_from_text(text, is_html=False)

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
        return self.extract_from_text(text)

    def extract_and_display(self, source):
        source_is_url = self.is_url(source)
        if source_is_url:
            results = self.extract_from_url(source)
            label = source
        else:
            results = self.extract_from_file(source)
            label = source
        if not results:
            return

        total_iocs = sum(len(v) for v in results.values())

        if is_text_output():
            neutral = mycolors.foreground.neutral(cv.bkg)

            print()
            print(mycolors.reset + "IOC EXTRACTION REPORT".center(REPORT_WIDTH))
            print(neutral + (REPORT_WIDTH * '-') + mycolors.reset)

            shown_label = defang(label) if (cv.defang and source_is_url) else label
            for name, value in (("Source", shown_label), ("Total IOCs", str(total_iocs))):
                print(
                    mycolors.foreground.info(cv.bkg)
                    + pad(name + ':', FIELD_WIDTH)
                    + mycolors.reset
                    + wrap_field(value, REPORT_WIDTH, FIELD_WIDTH, split_long=True)
                )
            print()

            for ioc_type, values in results.items():
                if not values:
                    continue
                print(
                    mycolors.foreground.info(cv.bkg)
                    + f"{ioc_type.upper()} ({len(values)}):"
                    + mycolors.reset
                )
                for val in sorted(values):
                    print("  " + (defang(val) if cv.defang else val))
                print()

            for line in self.suppression_notes():
                print(bullet(line, REPORT_WIDTH, neutral))

        collector.add({
            'source': label,
            'iocs': results,
        })
        printr()

    def suppression_notes(self):
        if not cv.ioc_filter:
            return []

        counts = getattr(self, 'suppressed', {}) or {}
        notes = []

        if counts:
            labels = {'domains': ('domain', 'domains'), 'urls': ('URL', 'URLs')}
            parts = ["%d %s" % (counts[key], labels[key][counts[key] != 1])
                     for key in ('domains', 'urls') if counts.get(key)]
            reasons = ["values whose last label is not a real top-level domain"]
            if getattr(self, 'source_site', ''):
                reasons.append("links back to %s" % self.source_site)
            reasons.append("known page furniture such as analytics, fonts and social buttons")
            notes.append("%s suppressed: %s, and %s."
                         % (" and ".join(parts), ", ".join(reasons[:-1]), reasons[-1]))

        if getattr(self, 'html_stripped', False):
            notes.append(
                "The source was HTML, so <script>, <style> and <svg> blocks were skipped and "
                "page code is not reported as indicators.")

        if notes:
            notes.append(
                "Suppressed values are not shown and are not exported. Re-run with "
                "--no-ioc-filter to extract from the raw source with no filtering at all.")
        return notes
