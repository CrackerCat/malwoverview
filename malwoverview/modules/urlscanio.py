import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import (
    mycolors, printr, strip_json_escapes, bullet, column, fit, pad, wrap_field,
)
from malwoverview.utils.session import create_session
from malwoverview.utils.cache import cached
from malwoverview.utils.output import collector, is_text_output
from urllib.parse import quote
import datetime
import json
import time


REPORT_WIDTH = 100
FIELD_GUTTER = 4

VERDICT_FIELDS = ('Malicious', 'Verdict Score', 'Categories', 'Tags', 'Brands')
CLEAN_VALUES = ('None', 'N/A', 'False', '0')
PIVOT_FIELDS = {'Contacted IPs': 'accent', 'Contacted Domains': 'warning'}
FIELD_BREAKS = ('Contacted IPs',)

COL_GUTTER = 2
COL_DOMAIN_MAX = 44
COL_IP_MAX = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
COL_CAPS = {'domain': COL_DOMAIN_MAX, 'ip': COL_IP_MAX}

SEARCH_HEADERS = ("Domain", "IP", "Country", "Status", "ASN", "Age(d)", "Date", "UUID")
SEARCH_KEYS = ('domain', 'ip', 'country', 'status', 'asn', 'age', 'date', 'uuid')

AGE_FRESH_DAYS = 30
AGE_RECENT_DAYS = 365

MAX_SEARCH_RESULTS = 30
MAX_CERTIFICATES = 5


class URLScanIOExtractor():
    urlbase = 'https://urlscan.io/api/v1'

    def __init__(self, URLSCANIOAPI):
        self.URLSCANIOAPI = URLSCANIOAPI

    def requestURLSCANIOAPI(self):
        if self.URLSCANIOAPI == '':
            print(mycolors.foreground.error(cv.bkg) + "\nTo be able to get information from URLScan.io, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the URLScan.io API key according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def _handle_status(self, response):
        if response.status_code == 401:
            return {'error': 'Unauthorized. Check your URLScan.io API key.'}
        if response.status_code == 403:
            return {'error': 'Access forbidden. Check your URLScan.io API permissions.'}
        if response.status_code == 404:
            return {'error': 'Resource not found.'}
        if response.status_code == 429:
            return {'error': 'Rate limit exceeded. Please wait and try again.'}
        return None

    def _search_widths(self, rows):
        widths = {}
        for index, key in enumerate(SEARCH_KEYS):
            header = SEARCH_HEADERS[index]
            values = [row[index] for row in rows]
            last = index == len(SEARCH_KEYS) - 1
            widths[key] = column(
                header, values,
                cap=COL_CAPS.get(key),
                gutter=0 if last else COL_GUTTER,
            )
        widths['total'] = sum(widths[key] for key in SEARCH_KEYS)
        return widths

    def _status_color(self, status):
        if status.isdigit():
            code = int(status)
            if 200 <= code < 300:
                return mycolors.foreground.ok(cv.bkg)
            if 500 <= code < 600:
                return mycolors.foreground.error(cv.bkg)
            return mycolors.foreground.warning(cv.bkg)
        return mycolors.foreground.neutral(cv.bkg)

    def _field_color(self, name, value):
        pivot = PIVOT_FIELDS.get(name)
        if pivot:
            return getattr(mycolors.foreground, pivot)(cv.bkg)
        if name in VERDICT_FIELDS:
            if value in CLEAN_VALUES:
                return mycolors.foreground.ok(cv.bkg)
            return mycolors.foreground.error(cv.bkg)
        return mycolors.foreground.success(cv.bkg)

    def _print_fields(self, fields, value_color=None):
        width = max(len(name) for name in fields) + len(':') + FIELD_GUTTER
        for position, (name, value) in enumerate(fields.items()):
            if position and name in FIELD_BREAKS:
                print()
            print(
                mycolors.foreground.info(cv.bkg) + pad(name + ':', width)
                + (value_color or self._field_color(name, value))
                + wrap_field(value, REPORT_WIDTH, width)
                + mycolors.reset
            )

    def _certificate_date(self, value):
        try:
            stamp = int(value)
        except (TypeError, ValueError):
            return str(value)
        try:
            return datetime.datetime.fromtimestamp(
                stamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (OSError, OverflowError, ValueError):
            return str(value)

    def _age_color(self, age):
        if not age.isdigit():
            return mycolors.foreground.neutral(cv.bkg)
        days = int(age)
        if days < AGE_FRESH_DAYS:
            return mycolors.foreground.error(cv.bkg)
        if days < AGE_RECENT_DAYS:
            return mycolors.foreground.warning(cv.bkg)
        return mycolors.foreground.ok(cv.bkg)

    def _print_search_title(self, width):
        print()
        print(mycolors.reset + "URLSCAN.IO SEARCH REPORT".center(width))
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
        domain, ip, country, status, asn, age, date, uuid = row
        print(
            mycolors.foreground.info(cv.bkg) + pad(fit(domain, widths['domain'] - COL_GUTTER), widths['domain'])
            + mycolors.foreground.accent(cv.bkg) + pad(fit(ip, widths['ip'] - COL_GUTTER), widths['ip'])
            + mycolors.foreground.success(cv.bkg) + pad(country, widths['country'])
            + self._status_color(status) + pad(status, widths['status'])
            + mycolors.foreground.info(cv.bkg) + pad(asn, widths['asn'])
            + self._age_color(age) + pad(age, widths['age'])
            + mycolors.foreground.success(cv.bkg) + pad(date, widths['date'])
            + mycolors.foreground.accent(cv.bkg) + uuid
            + mycolors.reset
        )

    def urlscanio_submit(self, url_to_scan):
        self.requestURLSCANIOAPI()

        url = f"{URLScanIOExtractor.urlbase}/scan/"
        headers = {
            'API-Key': self.URLSCANIOAPI,
            'Content-Type': 'application/json'
        }
        payload = {
            'url': url_to_scan,
            'visibility': 'public'
        }

        try:
            session = create_session(headers)
            response = session.post(url, json=payload, timeout=30)

            if is_text_output():
                print()
                print((mycolors.reset + "URLSCAN.IO SUBMISSION REPORT".center(REPORT_WIDTH)))
                print(mycolors.foreground.neutral(cv.bkg) + (REPORT_WIDTH * '-') + mycolors.reset)

            err = self._handle_status(response)
            if err:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{err['error']}\n" + mycolors.reset)
                return

            data = strip_json_escapes(response.json())

            if 'message' in data and 'uuid' not in data:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{data.get('message', 'Submission failed.')}\n" + mycolors.reset)
                return

            scan_uuid = str(data.get('uuid', 'N/A'))
            scan_url = str(data.get('result', 'N/A'))
            api_url = str(data.get('api', 'N/A'))
            visibility = str(data.get('visibility', 'N/A'))
            submitted_url = str(data.get('url', 'N/A'))

            record = {
                'uuid': scan_uuid,
                'url': submitted_url,
                'result_url': scan_url,
                'api_url': api_url,
                'visibility': visibility
            }
            collector.add(record)

            if is_text_output():
                fields = {
                    'UUID': scan_uuid,
                    'Submitted URL': submitted_url,
                    'Result Page': scan_url,
                    'API Result': api_url,
                    'Visibility': visibility,
                }

                COLSIZE = max(len(f) for f in fields.keys()) + 3

                for field, value in fields.items():
                    print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + value)

                print()
                print(bullet("A scan takes about 15 seconds. Retrieve it with -u 2 -U %s"
                             % scan_uuid,
                             REPORT_WIDTH, mycolors.foreground.neutral(cv.bkg)))

        except ValueError:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError parsing JSON response from URLScan.io.\n" + mycolors.reset)
        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    @cached("urlscanio_result")
    def _raw_result(self, uuid):
        self.requestURLSCANIOAPI()

        url = f"{URLScanIOExtractor.urlbase}/result/{quote(uuid, safe='')}/"
        headers = {
            'API-Key': self.URLSCANIOAPI,
            'Accept': 'application/json'
        }

        try:
            session = create_session(headers)
            response = session.get(url, timeout=30)

            err = self._handle_status(response)
            if err:
                return err

            data = strip_json_escapes(response.json())
            return data

        except ValueError:
            return {'error': 'Error parsing JSON response from URLScan.io.'}
        except Exception as e:
            return {'error': str(e)}

    def urlscanio_result(self, uuid):
        self.requestURLSCANIOAPI()

        data = self._raw_result(uuid)

        try:
            if is_text_output():
                print()
                print((mycolors.reset + "URLSCAN.IO SCAN RESULT".center(REPORT_WIDTH)))
                print(mycolors.foreground.neutral(cv.bkg) + (REPORT_WIDTH * '-') + mycolors.reset)

            if 'error' in data:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + f"\n{data['error']}\n" + mycolors.reset)
                return

            task = data.get('task', {})
            page = data.get('page', {})
            stats = data.get('stats', {})
            lists = data.get('lists', {})
            verdicts = data.get('verdicts', {})

            task_url = str(task.get('url', 'N/A'))
            task_domain = str(task.get('domain', 'N/A'))
            task_time = str(task.get('time', 'N/A'))
            task_visibility = str(task.get('visibility', 'N/A'))

            page_ip = str(page.get('ip', 'N/A'))
            page_country = str(page.get('country', 'N/A'))
            page_server = str(page.get('server', 'N/A'))
            page_title = str(page.get('title', 'N/A'))
            page_status = str(page.get('status', 'N/A'))
            page_mime = str(page.get('mimeType', 'N/A'))
            page_asn = str(page.get('asn', 'N/A'))
            page_asnname = str(page.get('asnname', 'N/A'))

            total_requests = str(stats.get('uniqIPs', 'N/A'))
            resource_count = str(stats.get('totalLinks', 'N/A'))

            overall_verdict = verdicts.get('overall', {})
            malicious = str(overall_verdict.get('malicious', False))
            score = str(overall_verdict.get('score', 0))
            verdict_categories = ', '.join(overall_verdict.get('categories', [])) or 'None'
            verdict_tags = ', '.join(overall_verdict.get('tags', [])) or 'None'
            verdict_brands = ', '.join(overall_verdict.get('brands', [])) or 'None'

            ips_list = lists.get('ips', [])
            domains_list = lists.get('domains', [])
            countries_list = lists.get('countries', [])

            ips_str = ', '.join(ips_list[:10])
            if len(ips_list) > 10:
                ips_str += f' (+{len(ips_list) - 10} more)'
            domains_str = ', '.join(domains_list[:10])
            if len(domains_list) > 10:
                domains_str += f' (+{len(domains_list) - 10} more)'
            countries_str = ', '.join(countries_list) if countries_list else 'N/A'

            record = {
                'url': task_url,
                'domain': task_domain,
                'ip': page_ip,
                'country': page_country,
                'server': page_server,
                'title': page_title,
                'status_code': page_status,
                'mime_type': page_mime,
                'asn': page_asn,
                'asn_name': page_asnname,
                'scan_time': task_time,
                'visibility': task_visibility,
                'unique_ips': total_requests,
                'total_links': resource_count,
                'malicious': malicious,
                'verdict_score': score,
                'verdict_categories': verdict_categories,
                'verdict_tags': verdict_tags,
                'verdict_brands': verdict_brands,
                'contacted_ips': ips_str,
                'contacted_domains': domains_str,
                'countries': countries_str
            }
            collector.add(record)

            if is_text_output():
                fields = {
                    'URL': task_url,
                    'Domain': task_domain,
                    'IP': page_ip,
                    'Country': page_country,
                    'ASN': page_asn,
                    'ASN Name': page_asnname,
                    'Server': page_server,
                    'Status Code': page_status,
                    'MIME Type': page_mime,
                    'Page Title': page_title,
                    'Scan Time': task_time,
                    'Visibility': task_visibility,
                    'Unique IPs': total_requests,
                    'Total Links': resource_count,
                    'Malicious': malicious,
                    'Verdict Score': score,
                    'Categories': verdict_categories,
                    'Tags': verdict_tags,
                    'Brands': verdict_brands,
                    'Contacted IPs': ips_str if ips_str else 'None',
                    'Contacted Domains': domains_str if domains_str else 'None',
                    'Countries': countries_str,
                }

                self._print_fields(fields)

                certs = data.get('lists', {}).get('certificates', [])
                if certs:
                    print()
                    print(mycolors.foreground.info(cv.bkg) + "SSL Certificates:" + mycolors.reset)
                    for cert in certs[:MAX_CERTIFICATES]:
                        print()
                        self._print_fields({
                            '  Subject': str(cert.get('subjectName', 'N/A')),
                            '  Issuer': str(cert.get('issuer', 'N/A')),
                            '  Valid From': self._certificate_date(cert.get('validFrom', 'N/A')),
                            '  Valid To': self._certificate_date(cert.get('validTo', 'N/A')),
                        }, value_color=mycolors.foreground.neutral(cv.bkg))
                    if len(certs) > MAX_CERTIFICATES:
                        print()
                        print(bullet("%d of %d certificates shown."
                                     % (MAX_CERTIFICATES, len(certs)),
                                     REPORT_WIDTH, mycolors.foreground.neutral(cv.bkg)))

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    def urlscanio_search(self, query):
        self.requestURLSCANIOAPI()

        url = f"{URLScanIOExtractor.urlbase}/search/"
        headers = {
            'API-Key': self.URLSCANIOAPI,
            'Accept': 'application/json'
        }
        params = {'q': query}

        try:
            session = create_session(headers)
            response = session.get(url, params=params, timeout=30)

            err = self._handle_status(response)
            if err:
                if is_text_output():
                    self._print_search_title(self._search_widths([])['total'])
                    print(mycolors.foreground.error(cv.bkg) + f"\n{err['error']}\n" + mycolors.reset)
                return

            data = strip_json_escapes(response.json())

            results = data.get('results', [])
            if not results:
                if is_text_output():
                    self._print_search_title(self._search_widths([])['total'])
                    print(mycolors.foreground.error(cv.bkg) + "\nNo results found for this query.\n" + mycolors.reset)
                return

            rows = []

            for result in results[:MAX_SEARCH_RESULTS]:
                task = result.get('task', {})
                page = result.get('page', {})

                task_uuid = str(result.get('_id', 'N/A'))
                task_time = str(task.get('time', 'N/A'))[:19]
                page_ip = str(page.get('ip', 'N/A'))
                page_domain = str(page.get('domain', 'N/A'))
                page_country = str(page.get('country', 'N/A'))
                page_status = str(page.get('status', 'N/A'))
                page_asn = str(page.get('asn', 'N/A'))

                page_age = page.get('domainAgeDays')
                page_apex_age = page.get('apexDomainAgeDays')
                age_cell = 'N/A' if page_age is None else str(page_age)

                record = {
                    'uuid': task_uuid,
                    'domain': page_domain,
                    'ip': page_ip,
                    'country': page_country,
                    'status_code': page_status,
                    'asn': page_asn,
                    'domain_age_days': age_cell,
                    'apex_domain_age_days': 'N/A' if page_apex_age is None else str(page_apex_age),
                    'scan_time': task_time,
                }
                collector.add(record)

                rows.append((page_domain, page_ip, page_country, page_status,
                             page_asn, age_cell, task_time, task_uuid))

            total = data.get('total', len(results))
            if is_text_output():
                widths = self._search_widths(rows)
                self._print_search_title(widths['total'])
                self._print_search_header(widths)
                for row in rows:
                    self._print_search_row(row, widths)

                fresh = sum(1 for row in rows
                            if row[5].isdigit() and int(row[5]) < AGE_FRESH_DAYS)

                structure = mycolors.foreground.neutral(cv.bkg)
                print()
                if total > MAX_SEARCH_RESULTS:
                    print(bullet("Showing %d of %d total results."
                                 % (len(rows), total), widths['total'], structure))
                    print(bullet("urlscan.io returned more matches than are shown. Narrow the "
                                 "query to bring the interesting ones into the first %d."
                                 % MAX_SEARCH_RESULTS, widths['total'], structure))
                else:
                    print(bullet("%d result(s) found." % len(rows),
                                 widths['total'], structure))
                if fresh:
                    print(bullet("Age(d) is the age of the scanned domain in days, as urlscan.io "
                                 "reports it. %d of these were registered less than %d days ago."
                                 % (fresh, AGE_FRESH_DAYS), widths['total'], structure))
                print(bullet("The search endpoint carries no verdict. Use -u 2 with a UUID from "
                             "the last column for the full scan result, which is where urlscan.io "
                             "reports its score, categories and brands.",
                             widths['total'], structure))

        except ValueError:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError parsing JSON response from URLScan.io.\n" + mycolors.reset)
        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

    def urlscanio_domain(self, domain):
        self.urlscanio_search(f"domain:{domain}")

    def urlscanio_ip(self, ip):
        self.urlscanio_search(f"page.ip:{ip}")
