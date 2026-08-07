import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printc, strip_json_escapes, report_header
from malwoverview.utils.output import collector, is_text_output
from malwoverview.utils.session import create_session
import ipaddress

REPORT_WIDTH = 100


class IPInfoExtractor:
    def __init__(self, IPINFOAPI):
        self.IPINFOAPI = IPINFOAPI

    def _raw_ip_info(self, ip_address):
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return {'error': {'message': 'Invalid IP address format'}}
        
        url = f"https://ipinfo.io/{ip_address}"
        headers = {}
        if self.IPINFOAPI:
            headers['Authorization'] = f'Bearer {self.IPINFOAPI}'

        try:
            requestsession = create_session(headers)
            response = requestsession.get(url, timeout=30)
            return strip_json_escapes(response.json())
        except Exception as e:
            return {'error': {'message': str(e)}}

    def get_ip_details(self, ip_address):
#        self.requestIPINFOAPI()
        
        data = self._raw_ip_info(ip_address)

        try:
            if is_text_output():
                print()
                print(report_header("IPINFO.IO REPORT", REPORT_WIDTH))

            if 'error' in data:
                printc(f"\n{data['error']['message']}\n", mycolors.foreground.error(cv.bkg))
                return False

            fields = ['ip', 'hostname', 'org', 'country', 'region', 'city', 'loc', 'postal', 'timezone']

            record = {'service': 'ipinfo', 'query': ip_address}
            for field in fields:
                if field in data:
                    record[field] = data[field]
            collector.add(record)

            if not is_text_output():
                return True

            COLSIZE = max(len(field) for field in fields) + 3

            for field in fields:
                if field in data:
                    print(mycolors.foreground.info(cv.bkg) + f"{field.title()}: ".ljust(COLSIZE) + mycolors.reset + str(data[field]))

            return True

        except Exception as e:
            printc(f"\nError: {str(e)}\n", mycolors.foreground.error(cv.bkg))
