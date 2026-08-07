import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import (
    mycolors, printr, strip_json_escapes, bullet, column, fit, pad,
    report_header,
)
from malwoverview.utils.session import create_session
from malwoverview.utils.cache import cached
from malwoverview.utils.config import redact_secret
from malwoverview.utils.output import collector, is_text_output
from urllib.parse import quote
import json
import re


REPORT_WIDTH = 100

SEARCH_HEADERS = ("IP", "Port", "Country", "Product", "Vulns", "Organization")
SEARCH_KEYS = ('ip', 'port', 'country', 'product', 'vulns', 'org')

COL_GUTTER = 2
COL_IP_MAX = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
COL_PRODUCT_MAX = 30
COL_ORG_MAX = 34
COL_CAPS = {'ip': COL_IP_MAX, 'product': COL_PRODUCT_MAX, 'org': COL_ORG_MAX}

SNIPPET_MAX = 200

SERVER_RE = re.compile(r'^Server:[ \t]*(.+)$', re.IGNORECASE | re.MULTILINE)
DATE_RE = re.compile(r'^Date:[ \t]*.*$', re.IGNORECASE | re.MULTILINE)


class ShodanExtractor():
    urlshodan = 'https://api.shodan.io'

    def __init__(self, SHODANAPI):
        self.SHODANAPI = SHODANAPI

    def requestSHODANAPI(self):
        if self.SHODANAPI == '':
            print(mycolors.foreground.error(cv.bkg) + "\nTo be able to get information from Shodan, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Shodan API key according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    @cached("shodan_ip")
    def _raw_ip_info(self, ip):
        self.requestSHODANAPI()

        url = f"{ShodanExtractor.urlshodan}/shodan/host/{quote(ip, safe='')}"
        headers = {'Accept': 'application/json'}
        params = {'key': self.SHODANAPI}

        try:
            session = create_session(headers)
            response = session.get(url, params=params, timeout=30)

            if response.status_code == 401:
                return {'error': 'Unauthorized. Check your Shodan API key.'}
            if response.status_code == 403:
                return {'error': 'Access forbidden. Your API plan may not support this query.'}
            if response.status_code == 404:
                return {'error': 'No information available for this IP.'}
            if response.status_code == 429:
                return {'error': 'Rate limit exceeded. Please wait and try again.'}

            data = strip_json_escapes(response.json())
            return data

        except ValueError:
            return {'error': 'Error parsing JSON response from Shodan.'}
        except Exception as e:
            return {'error': redact_secret(e, self.SHODANAPI)}

    def shodan_ip(self, ip):
        self.requestSHODANAPI()

        data = self._raw_ip_info(ip)

        try:
            if is_text_output():
                print()
                print(report_header("SHODAN IP REPORT", REPORT_WIDTH))

            if 'error' in data:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{data['error']}\n" + mycolors.reset)
                return

            ip_addr = str(data.get('ip_str', 'N/A'))
            org = str(data.get('org', 'N/A'))
            isp = str(data.get('isp', 'N/A'))
            os_info = str(data.get('os', 'N/A'))
            ports = ', '.join(str(p) for p in data.get('ports', []))
            vulns = ', '.join(data.get('vulns', []))
            hostnames = ', '.join(data.get('hostnames', []))
            city = str(data.get('city', 'N/A'))
            country = str(data.get('country_name', 'N/A'))
            last_update = str(data.get('last_update', 'N/A'))

            record = {
                'ip': ip_addr,
                'org': org,
                'isp': isp,
                'os': os_info,
                'ports': ports,
                'vulns': vulns,
                'hostnames': hostnames,
                'city': city,
                'country': country,
                'last_update': last_update
            }
            collector.add(record)

            if is_text_output():
                fields = {
                    'IP': ip_addr,
                    'Organization': org,
                    'ISP': isp,
                    'OS': os_info,
                    'Ports': ports if ports else 'N/A',
                    'Vulns': vulns if vulns else 'None',
                    'Hostnames': hostnames if hostnames else 'N/A',
                    'City': city,
                    'Country': country,
                    'Last Update': last_update
                }

                COLSIZE = max(len(field) for field in fields.keys()) + 3

                for field, value in fields.items():
                    if field == 'Vulns' and value != 'None':
                        print(mycolors.foreground.error(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)
                    else:
                        print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {redact_secret(e, self.SHODANAPI)}\n" + mycolors.reset)

    def _product_cell(self, match):
        product = str(match.get('product') or '').strip()
        if product:
            version = str(match.get('version') or '').strip()
            return ("%s %s" % (product, version)).strip()
        found = SERVER_RE.search(str(match.get('data') or ''))
        if found:
            return found.group(1).strip()
        return 'n/a'

    def _banner_snippet(self, match):
        text = DATE_RE.sub('', str(match.get('data') or ''))
        return ' '.join(text.split())[:SNIPPET_MAX]

    def _search_widths(self, rows):
        widths = {}
        for index, key in enumerate(SEARCH_KEYS):
            last = index == len(SEARCH_KEYS) - 1
            widths[key] = column(
                SEARCH_HEADERS[index], [row[index] for row in rows],
                cap=COL_CAPS.get(key),
                gutter=0 if last else COL_GUTTER,
            )
        widths['total'] = sum(widths[key] for key in SEARCH_KEYS)
        return widths

    def _product_color(self):
        if cv.bkg == 1:
            return mycolors.foreground.lightblue
        return mycolors.foreground.blue

    def _vulns_color(self, vulns):
        if not vulns.isdigit():
            return mycolors.foreground.neutral(cv.bkg)
        if int(vulns) > 0:
            return mycolors.foreground.error(cv.bkg)
        return mycolors.foreground.ok(cv.bkg)

    def _print_search_title(self, width):
        print()
        print(mycolors.reset + "SHODAN SEARCH REPORT".center(width))
        print(mycolors.foreground.neutral(cv.bkg) + (width * '-') + mycolors.reset)

    def _print_search_header(self, widths):
        structure = mycolors.foreground.neutral(cv.bkg)
        print()
        print(
            structure
            + "".join(pad(SEARCH_HEADERS[i], widths[key])
                      for i, key in enumerate(SEARCH_KEYS))
            + mycolors.reset
        )
        print(structure + (widths['total'] * '-') + mycolors.reset)

    def _print_search_row(self, row, widths):
        ip_addr, port, country, product, vulns, org = row
        print(
            mycolors.foreground.info(cv.bkg) + pad(fit(ip_addr, widths['ip'] - COL_GUTTER), widths['ip'])
            + mycolors.foreground.accent(cv.bkg) + pad(port, widths['port'])
            + mycolors.foreground.ok(cv.bkg) + pad(country, widths['country'])
            + self._product_color() + pad(fit(product, widths['product'] - COL_GUTTER), widths['product'])
            + self._vulns_color(vulns) + pad(vulns, widths['vulns'])
            + mycolors.foreground.accent(cv.bkg) + fit(org, widths['org'])
            + mycolors.reset
        )

    def shodan_search(self, query):
        self.requestSHODANAPI()

        url = f"{ShodanExtractor.urlshodan}/shodan/host/search"
        headers = {'Accept': 'application/json'}
        params = {'key': self.SHODANAPI, 'query': query}

        try:
            session = create_session(headers)
            response = session.get(url, params=params, timeout=30)

            if response.status_code == 401:
                if is_text_output():
                    self._print_search_title(self._search_widths([])['total'])
                    print(mycolors.foreground.error(cv.bkg) + "\nUnauthorized. Check your Shodan API key.\n" + mycolors.reset)
                return
            if response.status_code == 403:
                if is_text_output():
                    self._print_search_title(self._search_widths([])['total'])
                    print(mycolors.foreground.error(cv.bkg) + "\nAccess forbidden. Your API plan may not support this query.\n" + mycolors.reset)
                return
            if response.status_code == 404:
                if is_text_output():
                    self._print_search_title(self._search_widths([])['total'])
                    print(mycolors.foreground.error(cv.bkg) + "\nNo results found.\n" + mycolors.reset)
                return
            if response.status_code == 429:
                if is_text_output():
                    self._print_search_title(self._search_widths([])['total'])
                    print(mycolors.foreground.error(cv.bkg) + "\nRate limit exceeded. Please wait and try again.\n" + mycolors.reset)
                return

            data = strip_json_escapes(response.json())

            if 'matches' not in data or len(data['matches']) == 0:
                if is_text_output():
                    self._print_search_title(self._search_widths([])['total'])
                    print(mycolors.foreground.error(cv.bkg) + "\nNo results found for this query.\n" + mycolors.reset)
                return

            rows = []

            for match in data['matches']:
                ip_addr = str(match.get('ip_str') or 'n/a')
                port = str(match.get('port') or 'n/a')
                org = str(match.get('org') or 'n/a')
                country = str(match.get('location', {}).get('country_code') or 'n/a')
                product = self._product_cell(match)
                vulns = str(len(match.get('vulns') or {}))

                record = {
                    'ip': ip_addr,
                    'port': port,
                    'country': country,
                    'product': product,
                    'vulns': vulns,
                    'org': org,
                    'asn': str(match.get('asn') or 'n/a'),
                    'hostnames': ', '.join(match.get('hostnames') or []) or 'n/a',
                    'data_snippet': self._banner_snippet(match),
                }
                collector.add(record)

                rows.append((ip_addr, port, country, product, vulns, org))

            if is_text_output():
                widths = self._search_widths(rows)
                self._print_search_title(widths['total'])
                self._print_search_header(widths)
                for row in rows:
                    self._print_search_row(row, widths)

                structure = mycolors.foreground.neutral(cv.bkg)
                total = data.get('total', len(rows))
                flagged = sum(1 for row in rows if row[4].isdigit() and int(row[4]) > 0)

                print()
                if total > len(rows):
                    print(bullet("Showing %d of %d total results."
                                 % (len(rows), total), widths['total'], structure))
                else:
                    print(bullet("%d result(s) found." % len(rows),
                                 widths['total'], structure))
                if flagged:
                    print(bullet("Vulns counts the CVEs Shodan lists against the banner; %d of "
                                 "these hosts carry at least one. A count of 0 means none are "
                                 "listed, not that none exist."
                                 % flagged, widths['total'], structure))
                print(bullet("Product is what Shodan parsed from the banner, or the Server header "
                             "when it parsed nothing. The full banner is in the json and csv "
                             "records.", widths['total'], structure))

        except ValueError:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError parsing JSON response from Shodan.\n" + mycolors.reset)
        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {redact_secret(e, self.SHODANAPI)}\n" + mycolors.reset)
