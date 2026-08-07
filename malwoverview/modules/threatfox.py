import malwoverview.modules.configvars as cv
import requests
import json
from malwoverview.utils.colors import mycolors, printr, strip_json_escapes, report_header, divider, wrap_field
from malwoverview.utils.session import create_session, failure_message
from malwoverview.utils.output import collector, is_text_output, add_records


REPORT_WIDTH = 100
FIELD_WIDTH = 15
FAMILY_FIELD_WIDTH = 36


class ThreatFoxExtractor():
    urlthreatfox = 'https://threatfox-api.abuse.ch/api/v1/'

    def __init__(self,THREATFOXAPI):
        self.THREATFOXAPI = THREATFOXAPI

    def requestTHREATFOXAPI(self):
        if (self.THREATFOXAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to THREATFOX, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the THREATFOX API (Auth-Key) according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def threatfox_listiocs(self, bazaarx):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestTHREATFOXAPI()

        try:
            print("\n")
            print(report_header("THREATFOX REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.THREATFOXAPI})
            params = {'query': "get_iocs", 'days': int(bazaarx)}

            bazaarresponse = requestsession.post(
                url=bazaar,
                data=json.dumps(params)
            )
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
            add_records('threatfox', 'threatfox_listiocs', bazaartext)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.yellow + "\nioc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("id" in y):
                                    if d['id']:
                                        print(mycolors.foreground.yellow + "\nid: ".ljust(16) + mycolors.reset + wrap_field(d['id'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type" in y):
                                    if d['threat_type']:
                                        print(mycolors.foreground.yellow + "\nthreat_type: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type_desc" in y):
                                    if d['threat_type_desc']:
                                        print(mycolors.foreground.yellow + "\nthreat_desc: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type" in y):
                                    if d['ioc_type']:
                                        print(mycolors.foreground.yellow + "\nioc_type: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type_desc" in y):
                                    if d['ioc_type_desc']:
                                        print(mycolors.foreground.yellow + "\nioc_desc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware" in y):
                                    if d['malware']:
                                        print(mycolors.foreground.yellow + "\nmalware: ".ljust(16) + mycolors.reset + wrap_field(d['malware'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_printable" in y):
                                    if d['malware_printable']:
                                        print(mycolors.foreground.yellow + "\nmalware_desc: ".ljust(16) + mycolors.reset + wrap_field(d['malware_printable'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_alias" in y):
                                    if d['malware_alias']:
                                        print(mycolors.foreground.yellow + "\nmalware_alias: ".ljust(16) + mycolors.reset + wrap_field(d['malware_alias'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_malpedia" in y):
                                    if d['malware_malpedia']:
                                        print(mycolors.foreground.yellow + "\nmalpedia: ".ljust(16) + mycolors.reset + wrap_field(d['malware_malpedia'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("confidence_level" in y):
                                    if d['confidence_level']:
                                        print(mycolors.foreground.yellow + "\nconfidence: ".ljust(16) + mycolors.reset + wrap_field(str(d['confidence_level']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.yellow + "\nfirst_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['first_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.yellow + "\nlast_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['last_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.yellow + "\nreporter: ".ljust(16) + mycolors.reset + wrap_field(str(d['reporter']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reference" in y):
                                    if d['reference']:
                                        print(mycolors.foreground.yellow + "\nreference: ".ljust(16) + mycolors.reset + wrap_field(d['reference'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.yellow + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.red + "\nioc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("id" in y):
                                    if d['id']:
                                        print(mycolors.foreground.red + "\nid: ".ljust(16) + mycolors.reset + wrap_field(d['id'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type" in y):
                                    if d['threat_type']:
                                        print(mycolors.foreground.red + "\nthreat_type: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type_desc" in y):
                                    if d['threat_type_desc']:
                                        print(mycolors.foreground.red + "\nthreat_desc: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type" in y):
                                    if d['ioc_type']:
                                        print(mycolors.foreground.red + "\nioc_type: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type_desc" in y):
                                    if d['ioc_type_desc']:
                                        print(mycolors.foreground.red + "\nioc_desc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware" in y):
                                    if d['malware']:
                                        print(mycolors.foreground.red + "\nmalware: ".ljust(16) + mycolors.reset + wrap_field(d['malware'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_printable" in y):
                                    if d['malware_printable']:
                                        print(mycolors.foreground.red + "\nmalware_desc: ".ljust(16) + mycolors.reset + wrap_field(d['malware_printable'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_alias" in y):
                                    if d['malware_alias']:
                                        print(mycolors.foreground.red + "\nmalware_alias: ".ljust(16) + mycolors.reset + wrap_field(d['malware_alias'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_malpedia" in y):
                                    if d['malware_malpedia']:
                                        print(mycolors.foreground.red + "\nmalpedia: ".ljust(16) + mycolors.reset + wrap_field(d['malware_malpedia'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("confidence_level" in y):
                                    if d['confidence_level']:
                                        print(mycolors.foreground.red + "\nconfidence: ".ljust(16) + mycolors.reset + wrap_field(str(d['confidence_level']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.red + "\nfirst_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['first_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.red + "\nlast_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['last_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.red + "\nreporter: ".ljust(16) + mycolors.reset + wrap_field(str(d['reporter']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reference" in y):
                                    if d['reference']:
                                        print(mycolors.foreground.red + "\nreference: ".ljust(16) + mycolors.reset + wrap_field(d['reference'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.red + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            return True
        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'ThreatFox'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()

    def threatfox_searchiocs(self, bazaarx):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestTHREATFOXAPI()

        try:
            print("\n")
            print(report_header("THREATFOX REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.THREATFOXAPI})
            params = {'query': "search_ioc", 'search_term': bazaarx}
            bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
            add_records('threatfox', 'threatfox_searchiocs', bazaartext)

            if bazaartext['query_status'] == "no_result":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_search_term":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.yellow + "\nioc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.yellow + "\nid: ".ljust(16) + mycolors.reset + wrap_field(d['id'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type" in y):
                                    if d['threat_type']:
                                        print(mycolors.foreground.yellow + "\nthreat_type: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type_desc" in y):
                                    if d['threat_type_desc']:
                                        print(mycolors.foreground.yellow + "\nthreat_desc: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type" in y):
                                    if d['ioc_type']:
                                        print(mycolors.foreground.yellow + "\nioc_type: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type_desc" in y):
                                    if d['ioc_type_desc']:
                                        print(mycolors.foreground.yellow + "\nioc_desc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware" in y):
                                    if d['malware']:
                                        print(mycolors.foreground.yellow + "\nmalware: ".ljust(16) + mycolors.reset + wrap_field(d['malware'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_printable" in y):
                                    if d['malware_printable']:
                                        print(mycolors.foreground.yellow + "\nmalware_desc: ".ljust(16) + mycolors.reset + wrap_field(d['malware_printable'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_alias" in y):
                                    if d['malware_alias']:
                                        print(mycolors.foreground.yellow + "\nmalware_alias: ".ljust(16) + mycolors.reset + wrap_field(d['malware_alias'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_malpedia" in y):
                                    if d['malware_malpedia']:
                                        print(mycolors.foreground.yellow + "\nmalpedia: ".ljust(16) + mycolors.reset + wrap_field(d['malware_malpedia'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("confidence_level" in y):
                                    if d['confidence_level']:
                                        print(mycolors.foreground.yellow + "\nconfidence: ".ljust(16) + mycolors.reset + wrap_field(str(d['confidence_level']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.yellow + "\nfirst_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['first_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.yellow + "\nlast_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['last_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.yellow + "\nreporter: ".ljust(16) + mycolors.reset + wrap_field(str(d['reporter']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reference" in y):
                                    if d['reference']:
                                        print(mycolors.foreground.yellow + "\nreference: ".ljust(16) + mycolors.reset + wrap_field(d['reference'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.yellow + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.red + "\nioc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.red + "\nid: ".ljust(16) + mycolors.reset + wrap_field(d['id'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type" in y):
                                    if d['threat_type']:
                                        print(mycolors.foreground.red + "\nthreat_type: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type_desc" in y):
                                    if d['threat_type_desc']:
                                        print(mycolors.foreground.red + "\nthreat_desc: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type" in y):
                                    if d['ioc_type']:
                                        print(mycolors.foreground.red + "\nioc_type: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type_desc" in y):
                                    if d['ioc_type_desc']:
                                        print(mycolors.foreground.red + "\nioc_desc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware" in y):
                                    if d['malware']:
                                        print(mycolors.foreground.red + "\nmalware: ".ljust(16) + mycolors.reset + wrap_field(d['malware'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_printable" in y):
                                    if d['malware_printable']:
                                        print(mycolors.foreground.red + "\nmalware_desc: ".ljust(16) + mycolors.reset + wrap_field(d['malware_printable'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_alias" in y):
                                    if d['malware_alias']:
                                        print(mycolors.foreground.red + "\nmalware_alias: ".ljust(16) + mycolors.reset + wrap_field(d['malware_alias'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_malpedia" in y):
                                    if d['malware_malpedia']:
                                        print(mycolors.foreground.red + "\nmalpedia: ".ljust(16) + mycolors.reset + wrap_field(d['malware_malpedia'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("confidence_level" in y):
                                    if d['confidence_level']:
                                        print(mycolors.foreground.red + "\nconfidence: ".ljust(16) + mycolors.reset + wrap_field(str(d['confidence_level']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.red + "\nfirst_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['first_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.red + "\nlast_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['last_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.red + "\nreporter: ".ljust(16) + mycolors.reset + wrap_field(str(d['reporter']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reference" in y):
                                    if d['reference']:
                                        print(mycolors.foreground.red + "\nreference: ".ljust(16) + mycolors.reset + wrap_field(d['reference'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.red + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'ThreatFox'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()

    def threatfox_searchtags(self, bazaarx):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestTHREATFOXAPI()

        try:

            print("\n")
            print(report_header("THREATFOX REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.THREATFOXAPI})
            params = {'query': "taginfo", 'tag': bazaarx}
            bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
            add_records('threatfox', 'threatfox_searchtags', bazaartext)

            if bazaartext['query_status'] == "no_result":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_search_term":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_tag":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe tag you have provided is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe tag you have provided is not valid!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.lightcyan + "\nioc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.lightcyan + "\nid: ".ljust(16) + mycolors.reset + wrap_field(d['id'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type" in y):
                                    if d['threat_type']:
                                        print(mycolors.foreground.lightcyan + "\nthreat_type: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type_desc" in y):
                                    if d['threat_type_desc']:
                                        print(mycolors.foreground.lightcyan + "\nthreat_desc: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type" in y):
                                    if d['ioc_type']:
                                        print(mycolors.foreground.lightcyan + "\nioc_type: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type_desc" in y):
                                    if d['ioc_type_desc']:
                                        print(mycolors.foreground.lightcyan + "\nioc_desc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware" in y):
                                    if d['malware']:
                                        print(mycolors.foreground.lightcyan + "\nmalware: ".ljust(16) + mycolors.reset + wrap_field(d['malware'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_printable" in y):
                                    if d['malware_printable']:
                                        print(mycolors.foreground.lightcyan + "\nmalware_desc: ".ljust(16) + mycolors.reset + wrap_field(d['malware_printable'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_alias" in y):
                                    if d['malware_alias']:
                                        print(mycolors.foreground.lightcyan + "\nmalware_alias: ".ljust(16) + mycolors.reset + wrap_field(d['malware_alias'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_malpedia" in y):
                                    if d['malware_malpedia']:
                                        print(mycolors.foreground.lightcyan + "\nmalpedia: ".ljust(16) + mycolors.reset + wrap_field(d['malware_malpedia'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("confidence_level" in y):
                                    if d['confidence_level']:
                                        print(mycolors.foreground.lightcyan + "\nconfidence: ".ljust(16) + mycolors.reset + wrap_field(str(d['confidence_level']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.lightcyan + "\nfirst_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['first_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.lightcyan + "\nlast_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['last_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.lightcyan + "\nreporter: ".ljust(16) + mycolors.reset + wrap_field(str(d['reporter']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reference" in y):
                                    if d['reference']:
                                        print(mycolors.foreground.lightcyan + "\nreference: ".ljust(16) + mycolors.reset + wrap_field(d['reference'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.lightcyan + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.blue + "\nioc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.blue + "\nid: ".ljust(16) + mycolors.reset + wrap_field(d['id'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type" in y):
                                    if d['threat_type']:
                                        print(mycolors.foreground.blue + "\nthreat_type: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type_desc" in y):
                                    if d['threat_type_desc']:
                                        print(mycolors.foreground.blue + "\nthreat_desc: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type" in y):
                                    if d['ioc_type']:
                                        print(mycolors.foreground.blue + "\nioc_type: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type_desc" in y):
                                    if d['ioc_type_desc']:
                                        print(mycolors.foreground.blue + "\nioc_desc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware" in y):
                                    if d['malware']:
                                        print(mycolors.foreground.blue + "\nmalware: ".ljust(16) + mycolors.reset + wrap_field(d['malware'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_printable" in y):
                                    if d['malware_printable']:
                                        print(mycolors.foreground.blue + "\nmalware_desc: ".ljust(16) + mycolors.reset + wrap_field(d['malware_printable'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_alias" in y):
                                    if d['malware_alias']:
                                        print(mycolors.foreground.blue + "\nmalware_alias: ".ljust(16) + mycolors.reset + wrap_field(d['malware_alias'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_malpedia" in y):
                                    if d['malware_malpedia']:
                                        print(mycolors.foreground.blue + "\nmalpedia: ".ljust(16) + mycolors.reset + wrap_field(d['malware_malpedia'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("confidence_level" in y):
                                    if d['confidence_level']:
                                        print(mycolors.foreground.blue + "\nconfidence: ".ljust(16) + mycolors.reset + wrap_field(str(d['confidence_level']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.blue + "\nfirst_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['first_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.blue + "\nlast_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['last_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.blue + "\nreporter: ".ljust(16) + mycolors.reset + wrap_field(str(d['reporter']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reference" in y):
                                    if d['reference']:
                                        print(mycolors.foreground.blue + "\nreference: ".ljust(16) + mycolors.reset + wrap_field(d['reference'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.blue + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'ThreatFox'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()

    def threatfox_searchmalware(self, bazaarx):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestTHREATFOXAPI()

        try:

            print("\n")
            print(report_header("THREATFOX REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.THREATFOXAPI})
            params = {'query': "malwareinfo", 'malware': bazaarx}
            bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
            add_records('threatfox', 'threatfox_searchmalware', bazaartext)

            if bazaartext['query_status'] == "no_result":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_search_term":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe search term you have provided is not valid!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.lightcyan + "\nioc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.lightcyan + "\nid: ".ljust(16) + mycolors.reset + wrap_field(d['id'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type" in y):
                                    if d['threat_type']:
                                        print(mycolors.foreground.lightcyan + "\nthreat_type: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type_desc" in y):
                                    if d['threat_type_desc']:
                                        print(mycolors.foreground.lightcyan + "\nthreat_desc: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type" in y):
                                    if d['ioc_type']:
                                        print(mycolors.foreground.lightcyan + "\nioc_type: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type_desc" in y):
                                    if d['ioc_type_desc']:
                                        print(mycolors.foreground.lightcyan + "\nioc_desc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware" in y):
                                    if d['malware']:
                                        print(mycolors.foreground.lightcyan + "\nmalware: ".ljust(16) + mycolors.reset + wrap_field(d['malware'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_printable" in y):
                                    if d['malware_printable']:
                                        print(mycolors.foreground.lightcyan + "\nmalware_desc: ".ljust(16) + mycolors.reset + wrap_field(d['malware_printable'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_alias" in y):
                                    if d['malware_alias']:
                                        print(mycolors.foreground.lightcyan + "\nmalware_alias: ".ljust(16) + mycolors.reset + wrap_field(d['malware_alias'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_malpedia" in y):
                                    if d['malware_malpedia']:
                                        print(mycolors.foreground.lightcyan + "\nmalpedia: ".ljust(16) + mycolors.reset + wrap_field(d['malware_malpedia'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("confidence_level" in y):
                                    if d['confidence_level']:
                                        print(mycolors.foreground.lightcyan + "\nconfidence: ".ljust(16) + mycolors.reset + wrap_field(str(d['confidence_level']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.lightcyan + "\nfirst_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['first_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.lightcyan + "\nlast_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['last_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.lightcyan + "\nreporter: ".ljust(16) + mycolors.reset + wrap_field(str(d['reporter']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reference" in y):
                                    if d['reference']:
                                        print(mycolors.foreground.lightcyan + "\nreference: ".ljust(16) + mycolors.reset + wrap_field(d['reference'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.lightcyan + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("ioc" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.green + "\nioc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("id" in y):
                                    if d['ioc']:
                                        print(mycolors.foreground.green + "\nid: ".ljust(16) + mycolors.reset + wrap_field(d['id'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type" in y):
                                    if d['threat_type']:
                                        print(mycolors.foreground.green + "\nthreat_type: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("threat_type_desc" in y):
                                    if d['threat_type_desc']:
                                        print(mycolors.foreground.green + "\nthreat_desc: ".ljust(16) + mycolors.reset + wrap_field(d['threat_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type" in y):
                                    if d['ioc_type']:
                                        print(mycolors.foreground.green + "\nioc_type: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("ioc_type_desc" in y):
                                    if d['ioc_type_desc']:
                                        print(mycolors.foreground.green + "\nioc_desc: ".ljust(16) + mycolors.reset + wrap_field(d['ioc_type_desc'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware" in y):
                                    if d['malware']:
                                        print(mycolors.foreground.green + "\nmalware: ".ljust(16) + mycolors.reset + wrap_field(d['malware'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_printable" in y):
                                    if d['malware_printable']:
                                        print(mycolors.foreground.green + "\nmalware_desc: ".ljust(16) + mycolors.reset + wrap_field(d['malware_printable'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_alias" in y):
                                    if d['malware_alias']:
                                        print(mycolors.foreground.green + "\nmalware_alias: ".ljust(16) + mycolors.reset + wrap_field(d['malware_alias'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("malware_malpedia" in y):
                                    if d['malware_malpedia']:
                                        print(mycolors.foreground.green + "\nmalpedia: ".ljust(16) + mycolors.reset + wrap_field(d['malware_malpedia'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("confidence_level" in y):
                                    if d['confidence_level']:
                                        print(mycolors.foreground.green + "\nconfidence: ".ljust(16) + mycolors.reset + wrap_field(str(d['confidence_level']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.green + "\nfirst_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['first_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.green + "\nlast_seen: ".ljust(16) + mycolors.reset + wrap_field(str(d['last_seen']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.green + "\nreporter: ".ljust(16) + mycolors.reset + wrap_field(str(d['reporter']), REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("reference" in y):
                                    if d['reference']:
                                        print(mycolors.foreground.green + "\nreference: ".ljust(16) + mycolors.reset + wrap_field(d['reference'], REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.green + "\ntags: ".ljust(16), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'ThreatFox'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()

    def threatfox_listmalware(self):
        bazaar = ThreatFoxExtractor.urlthreatfox

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestTHREATFOXAPI()

        try:

            if is_text_output():
                print("\n")
                print(report_header("THREATFOX REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.THREATFOXAPI})
            params = {'query': "malware_list"}
            bazaarresponse = requestsession.post(url=bazaar, data=json.dumps(params))
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))

            if bazaartext['query_status'] == "no_result":
                if is_text_output():
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nYour search did not yield any result!\n" + mycolors.reset)
                    else:
                        print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                    printr()
                return False

            families = bazaartext.get('data') or {}

            for reference, info in families.items():
                record = {'malware_family': reference}
                if isinstance(info, dict):
                    for key in info:
                        record[key] = info[key]
                collector.add(record)

            if is_text_output():
                headcolor = mycolors.foreground.yellow if (cv.bkg == 1) else mycolors.foreground.purple
                for reference, info in families.items():
                    print("\n" + divider(REPORT_WIDTH), end=' ')
                    print(headcolor + "\nmalware_family: ".ljust(16) + mycolors.reset + wrap_field(reference, REPORT_WIDTH, FIELD_WIDTH, split_long=True), end=' ')
                    if isinstance(info, dict):
                        for key in info:
                            print(mycolors.reset + "\n".ljust(17) + "%-18s" % key + ': ', end='')
                            print(wrap_field(str(info[key]), REPORT_WIDTH, FAMILY_FIELD_WIDTH, split_long=True), end='')

                printr()

            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'ThreatFox'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to ThreatFox!\n"))
            printr()
