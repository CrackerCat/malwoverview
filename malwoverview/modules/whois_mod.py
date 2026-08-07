import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr, pad, wrap_field, strip_terminal_escapes
from malwoverview.utils.session import create_session
from malwoverview.utils.output import collector, is_text_output
import json


REPORT_WIDTH = 100
FIELD_WIDTH = 24


class WhoisExtractor():
    def __init__(self):
        pass

    @staticmethod
    def _clean(value):
        return strip_terminal_escapes(str(value))

    def _print_field(self, name, value, color):
        print(color + pad(name + ':', FIELD_WIDTH)
              + mycolors.reset
              + wrap_field(self._clean(value), REPORT_WIDTH, FIELD_WIDTH))

    def domain_whois(self, domain):
        try:
            import whois
        except ImportError:
            print(mycolors.foreground.error(cv.bkg) + "\nThe 'python-whois' package is required for WHOIS lookups. Please install it:" + mycolors.reset)
            print(mycolors.foreground.error(cv.bkg) + "\n    pip install python-whois\n" + mycolors.reset)
            exit(1)

        try:
            print("\n")
            print(mycolors.reset + "WHOIS DOMAIN REPORT".center(REPORT_WIDTH))
            print(mycolors.foreground.neutral(cv.bkg) + (REPORT_WIDTH * '-') + mycolors.reset)

            w = whois.whois(domain)

            infocolor = mycolors.foreground.info(cv.bkg)
            errorcolor = mycolors.foreground.error(cv.bkg)

            fields = {
                'Domain Name': w.domain_name,
                'Registrar': w.registrar,
                'Creation Date': w.creation_date,
                'Expiration Date': w.expiration_date,
                'Updated Date': w.updated_date,
                'Name Servers': w.name_servers,
                'Status': w.status,
                'Emails': w.emails,
                'Organization': w.org,
                'Country': w.country
            }

            for field_name, field_value in fields.items():
                if isinstance(field_value, list):
                    display_value = ', '.join([self._clean(v) for v in field_value])
                else:
                    display_value = self._clean(field_value) if field_value is not None else 'N/A'

                if is_text_output():
                    if field_name in ('Expiration Date', 'Status'):
                        self._print_field(field_name, display_value, errorcolor)
                    else:
                        self._print_field(field_name, display_value, infocolor)

                collector.start_record()
                collector.field('field', field_name)
                collector.field('value', display_value)
                collector.end_record()

        except Exception as e:
            print(mycolors.foreground.error(cv.bkg) + "\nError: " + str(e) + "\n")

        print(mycolors.reset)

    def ip_whois(self, ip):
        try:
            from ipwhois import IPWhois
        except ImportError:
            print(mycolors.foreground.error(cv.bkg) + "\nThe 'ipwhois' package is required for IP WHOIS lookups. Please install it:" + mycolors.reset)
            print(mycolors.foreground.error(cv.bkg) + "\n    pip install ipwhois\n" + mycolors.reset)
            exit(1)

        try:
            print("\n")
            print(mycolors.reset + "WHOIS IP REPORT".center(REPORT_WIDTH))
            print(mycolors.foreground.neutral(cv.bkg) + (REPORT_WIDTH * '-') + mycolors.reset)

            obj = IPWhois(ip)
            result = obj.lookup_rdap()

            infocolor = mycolors.foreground.info(cv.bkg)
            errorcolor = mycolors.foreground.error(cv.bkg)

            network = result.get('network', {}) or {}
            entities = result.get('entities', []) or []

            fields = {
                'ASN': result.get('asn', 'N/A'),
                'ASN Description': result.get('asn_description', 'N/A'),
                'ASN Country Code': result.get('asn_country_code', 'N/A'),
                'Network Name': network.get('name', 'N/A'),
                'Network CIDR': network.get('cidr', 'N/A'),
                'Entities': ', '.join(entities) if entities else 'N/A'
            }

            for field_name, field_value in fields.items():
                display_value = self._clean(field_value) if field_value is not None else 'N/A'

                if is_text_output():
                    if field_name == 'ASN':
                        self._print_field(field_name, display_value, errorcolor)
                    else:
                        self._print_field(field_name, display_value, infocolor)

                collector.start_record()
                collector.field('field', field_name)
                collector.field('value', display_value)
                collector.end_record()

        except Exception as e:
            print(mycolors.foreground.error(cv.bkg) + "\nError: " + str(e) + "\n")

        print(mycolors.reset)
