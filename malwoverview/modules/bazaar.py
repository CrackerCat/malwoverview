import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr, strip_json_escapes, strip_terminal_escapes, display_width, pad, fit, bullet, column, report_header, divider
import requests
import json
import os
import stat
import time
import zipfile
from malwoverview.utils.session import create_session, failure_message
from malwoverview.utils.hash import sha256hash
from malwoverview.utils.cache import cached
from malwoverview.utils.output import collector, is_text_output, add_records

REPORT_WIDTH = 100

COL_YARA_HASH = 66
COL_YARA_FILENAME = 34
COL_YARA_TYPE = 10
COL_YARA_SIGNATURE = 20
COL_YARA_FIRSTSEEN = 21
YARA_TABLE_WIDTH = COL_YARA_HASH + COL_YARA_FILENAME + COL_YARA_TYPE + COL_YARA_SIGNATURE + COL_YARA_FIRSTSEEN

BATCH_GUTTER = 2
BATCH_COL_FILENAME = 42
BATCH_COL_TYPE = 8
BATCH_COL_SIGNATURE = 17
BATCH_COL_TAGS = 40
BATCH_MAX_TAGS = 4
BATCH_HEADERS = ("Filename", "Hash", "Type", "Signature", "Tags")

YARA_LIMIT_MIN = 1
YARA_LIMIT_MAX = 1000
YARA_LIMIT_DEFAULT = 100

YARAIFY_RULES_URL = 'https://yaraify.abuse.ch/yarahub/yaraify-rules.zip'
YARAIFY_RULES_FILENAME = 'yaraify-rules.zip'
YARAIFY_RULES_DIRNAME = 'yaraify-rules'
YARAIFY_REFRESH_INTERVAL = 300

MAX_RULESET_DOWNLOAD_SIZE = 500 * 1024 * 1024
MAX_RULESET_ENTRIES = 100000
MAX_RULESET_MEMBERS = 20000
MAX_RULESET_TOTAL_BYTES = 200 * 1024 * 1024
MAX_RULESET_MEMBER_BYTES = 8 * 1024 * 1024
YARA_RULE_EXTENSIONS = ('.yar', '.yara')


def _ellipsis(value, width):
    text = str(value)
    if display_width(text) <= width:
        return text
    if width <= 3:
        return fit(text, width, marker='')
    return fit(text, width)


def _member_parts(name):
    return [p for p in name.replace('\\', '/').split('/') if p and p != '.']


def _unsafe_member_name(name):
    if not name:
        return True

    if any(ord(c) < 32 for c in name):
        return True

    normalized = name.replace('\\', '/')

    if normalized.startswith('/'):
        return True

    if len(normalized) > 1 and normalized[1] == ':':
        return True

    parts = _member_parts(name)

    if not parts:
        return True

    return any(p == '..' for p in parts)


def _inside_directory(root, target):
    rootn = os.path.normcase(root)
    targetn = os.path.normcase(target)

    if rootn == targetn:
        return False

    try:
        return os.path.commonpath([rootn, targetn]) == rootn
    except ValueError:
        return False


class BazaarExtractor():
    urlbazaar = 'https://mb-api.abuse.ch/api/v1/'

    def __init__(self, BAZAARAPI):
        self.BAZAARAPI = BAZAARAPI

    def requestBAZAARAPI(self):
        if (self.BAZAARAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Malware Bazaar, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Malware Bazaar API (Auth-Key) according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def bazaar_tag(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar
        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestBAZAARAPI()

        try:
            print("\n")
            print(report_header("MALWARE BAZAAR REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_taginfo', "tag": bazaarx, "limit": 50}
            bazaarresponse = requestsession.post(bazaar, data=params)
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
            add_records('bazaar', 'bazaar_tag', bazaartext)

            if bazaartext['query_status'] == "tag_not_found":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided tag was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided tag was not found!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_tag":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided tag is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided tag is not valid!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "no_results":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour query yield no results!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour query yield no results!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.lightcyan + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

                                if ("sha1_hash" in y):
                                    if d['sha1_hash']:
                                        print(mycolors.foreground.lightcyan + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                                if ("md5_hash" in y):
                                    if d['md5_hash']:
                                        print(mycolors.foreground.lightcyan + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.lightcyan + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.lightcyan + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                                if ("file_name" in y):
                                    if d['file_name']:
                                        print(mycolors.foreground.lightcyan + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                                if ("file_size" in y):
                                    if d['file_size']:
                                        print(mycolors.foreground.lightcyan + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                                if ("file_type" in y):
                                    if d['file_type']:
                                        print(mycolors.foreground.lightcyan + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                                if ("file_type_mime" in y):
                                    if d['file_type_mime']:
                                        print(mycolors.foreground.lightcyan + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                                if ("origin_country" in y):
                                    if d['origin_country']:
                                        print(mycolors.foreground.lightcyan + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                                if ("imphash" in y):
                                    if d['imphash']:
                                        print(mycolors.foreground.lightcyan + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                                if ("tlsh" in y):
                                    if d['tlsh']:
                                        print(mycolors.foreground.lightcyan + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.lightcyan + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                                if ("signature" in y):
                                    if d['signature']:
                                        print(mycolors.foreground.lightcyan + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.lightcyan + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.blue + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

                                if ("sha1_hash" in y):
                                    if d['sha1_hash']:
                                        print(mycolors.foreground.blue + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                                if ("md5_hash" in y):
                                    if d['md5_hash']:
                                        print(mycolors.foreground.blue + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.blue + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.blue + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                                if ("file_name" in y):
                                    if d['file_name']:
                                        print(mycolors.foreground.blue + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                                if ("file_size" in y):
                                    if d['file_size']:
                                        print(mycolors.foreground.blue + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                                if ("file_type" in y):
                                    if d['file_type']:
                                        print(mycolors.foreground.blue + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                                if ("file_type_mime" in y):
                                    if d['file_type_mime']:
                                        print(mycolors.foreground.blue + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                                if ("origin_country" in y):
                                    if d['origin_country']:
                                        print(mycolors.foreground.blue + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                                if ("imphash" in y):
                                    if d['imphash']:
                                        print(mycolors.foreground.blue + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                                if ("tlsh" in y):
                                    if d['tlsh']:
                                        print(mycolors.foreground.blue + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.blue + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                                if ("signature" in y):
                                    if d['signature']:
                                        print(mycolors.foreground.blue + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.blue + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'MalwareBazaar'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_imphash(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar
        bazaartext = ''
        params = ''

        self.requestBAZAARAPI()

        try:

            print("\n")
            print(report_header("MALWARE BAZAAR REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_imphash', "imphash": bazaarx, "limit": 50}
            bazaarresponse = requestsession.post(bazaar, data=params)
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
            add_records('bazaar', 'bazaar_imphash', bazaartext)

            if bazaartext['query_status'] == "imphash_not_found":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided imphash was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided imphash was not found!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_imphash":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided imphash is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided imphash is not valid!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "no_results":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYour query yield no results!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour query yield no results!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.pink + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

                                if ("sha1_hash" in y):
                                    if d['sha1_hash']:
                                        print(mycolors.foreground.pink + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                                if ("md5_hash" in y):
                                    if d['md5_hash']:
                                        print(mycolors.foreground.pink + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.pink + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.pink + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                                if ("file_name" in y):
                                    if d['file_name']:
                                        print(mycolors.foreground.pink + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                                if ("file_size" in y):
                                    if d['file_size']:
                                        print(mycolors.foreground.pink + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                                if ("file_type" in y):
                                    if d['file_type']:
                                        print(mycolors.foreground.pink + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                                if ("file_type_mime" in y):
                                    if d['file_type_mime']:
                                        print(mycolors.foreground.pink + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                                if ("origin_country" in y):
                                    if d['origin_country']:
                                        print(mycolors.foreground.pink + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                                if ("imphash" in y):
                                    if d['imphash']:
                                        print(mycolors.foreground.pink + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                                if ("tlsh" in y):
                                    if d['tlsh']:
                                        print(mycolors.foreground.pink + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.pink + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                                if ("signature" in y):
                                    if d['signature']:
                                        print(mycolors.foreground.pink + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.pink + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.purple + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

                                if ("sha1_hash" in y):
                                    if d['sha1_hash']:
                                        print(mycolors.foreground.purple + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                                if ("md5_hash" in y):
                                    if d['md5_hash']:
                                        print(mycolors.foreground.purple + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.purple + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.purple + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                                if ("file_name" in y):
                                    if d['file_name']:
                                        print(mycolors.foreground.purple + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                                if ("file_size" in y):
                                    if d['file_size']:
                                        print(mycolors.foreground.purple + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                                if ("file_type" in y):
                                    if d['file_type']:
                                        print(mycolors.foreground.purple + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                                if ("file_type_mime" in y):
                                    if d['file_type_mime']:
                                        print(mycolors.foreground.purple + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                                if ("origin_country" in y):
                                    if d['origin_country']:
                                        print(mycolors.foreground.purple + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                                if ("imphash" in y):
                                    if d['imphash']:
                                        print(mycolors.foreground.purple + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                                if ("tlsh" in y):
                                    if d['tlsh']:
                                        print(mycolors.foreground.purple + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.purple + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                                if ("signature" in y):
                                    if d['signature']:
                                        print(mycolors.foreground.purple + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.purple + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'MalwareBazaar'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_lastsamples(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestBAZAARAPI()

        try:
            print("\n")
            print(report_header("MALWARE BAZAAR REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_recent', "selector": bazaarx}
            bazaarresponse = requestsession.post(bazaar, data=params)
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
            add_records('bazaar', 'bazaar_lastsamples', bazaartext)

            if bazaartext['query_status'] == "unknown_selector":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYou didn't provide a valid selector!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYour search did not yield any result!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "no_results":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe query yield no results!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe query yield no results!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.yellow + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

                                if ("sha1_hash" in y):
                                    if d['sha1_hash']:
                                        print(mycolors.foreground.yellow + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                                if ("md5_hash" in y):
                                    if d['md5_hash']:
                                        print(mycolors.foreground.yellow + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.yellow + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.yellow + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                                if ("file_name" in y):
                                    if d['file_name']:
                                        print(mycolors.foreground.yellow + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                                if ("file_size" in y):
                                    if d['file_size']:
                                        print(mycolors.foreground.yellow + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                                if ("file_type" in y):
                                    if d['file_type']:
                                        print(mycolors.foreground.yellow + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                                if ("file_type_mime" in y):
                                    if d['file_type_mime']:
                                        print(mycolors.foreground.yellow + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                                if ("origin_country" in y):
                                    if d['origin_country']:
                                        print(mycolors.foreground.yellow + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                                if ("imphash" in y):
                                    if d['imphash']:
                                        print(mycolors.foreground.yellow + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                                if ("tlsh" in y):
                                    if d['tlsh']:
                                        print(mycolors.foreground.yellow + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.yellow + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                                if ("signature" in y):
                                    if d['signature']:
                                        print(mycolors.foreground.yellow + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.yellow + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                print("\n" + divider(REPORT_WIDTH), end=' ')
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.blue + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

                                if ("sha1_hash" in y):
                                    if d['sha1_hash']:
                                        print(mycolors.foreground.blue + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                                if ("md5_hash" in y):
                                    if d['md5_hash']:
                                        print(mycolors.foreground.blue + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.blue + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.blue + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                                if ("file_name" in y):
                                    if d['file_name']:
                                        print(mycolors.foreground.blue + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                                if ("file_size" in y):
                                    if d['file_size']:
                                        print(mycolors.foreground.blue + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                                if ("file_type" in y):
                                    if d['file_type']:
                                        print(mycolors.foreground.blue + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                                if ("file_type_mime" in y):
                                    if d['file_type_mime']:
                                        print(mycolors.foreground.blue + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                                if ("origin_country" in y):
                                    if d['origin_country']:
                                        print(mycolors.foreground.blue + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                                if ("imphash" in y):
                                    if d['imphash']:
                                        print(mycolors.foreground.blue + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                                if ("tlsh" in y):
                                    if d['tlsh']:
                                        print(mycolors.foreground.blue + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.blue + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                                if ("signature" in y):
                                    if d['signature']:
                                        print(mycolors.foreground.blue + "\nsignature: ".ljust(15) + mycolors.reset + d['signature'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.blue + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

            printr()
            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'MalwareBazaar'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_download(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar

        bazaartext = ''
        bazaarresponse = ''
        params = ''
        resource = bazaarx

        self.requestBAZAARAPI()

        try:
            print("\n")
            print(report_header("MALWARE BAZAAR REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/gzip'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_file', "sha256_hash": bazaarx}
            bazaarresponse = requestsession.post(bazaar, data=params, allow_redirects=False, stream=True, timeout=60)
            
            MAX_DOWNLOAD_SIZE = 500 * 1024 * 1024
            content = bytearray()
            for chunk in bazaarresponse.iter_content(chunk_size=8192):
                if chunk:
                    content += chunk
                    if len(content) > MAX_DOWNLOAD_SIZE:
                        print(mycolors.foreground.red + "\nError: File too large (>500MB). Download aborted.\n" + mycolors.reset)
                        exit(1)
            bazaartext = content.decode('utf-8', errors='ignore')

            if "illegal_sha256_hash" in bazaartext:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nYou didn't provide a valid sha256 hash!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nYou didn't provide a valid selector!\n" + mycolors.reset)
                exit(1)

            if "file_not_found" in bazaartext:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nNo malware samples found for the provided sha256 hash!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nNo malware samples found for the provided sha256 hash!\n" + mycolors.reset)
                exit(1)

            safe_filename = os.path.basename(resource) + '.zip'
            outputpath = os.path.join(cv.output_dir, safe_filename)
            with open(outputpath, 'wb') as f:
                f.write(content)
                collector.add({'service': 'bazaar', 'query_type': 'bazaar_download', 'query': bazaarx, 'file': outputpath, 'size': os.path.getsize(outputpath)})
            final = f'\nSample downloaded to: {outputpath}'

            if (cv.bkg == 1):
                print((mycolors.foreground.yellow + final + "\n"))
            else:
                print((mycolors.foreground.green + final + "\n"))

            printr()
            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'MalwareBazaar'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "Error while connecting to Malware Bazaar!\n"))
            printr()

    def bazaar_hash(self, bazaarx):
        bazaar = BazaarExtractor.urlbazaar

        bazaartext = ''
        bazaarresponse = ''
        params = ''

        self.requestBAZAARAPI()

        try:
            print("\n")
            print(report_header("MALWARE BAZAAR REPORT", REPORT_WIDTH))

            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_info', "hash": bazaarx}
            bazaarresponse = requestsession.post(bazaar, data=params)
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
            add_records('bazaar', 'bazaar_hash', bazaartext)

            if bazaartext['query_status'] == "hash_not_found":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided hash was not found!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided hash was not found!\n" + mycolors.reset)
                exit(1)

            if bazaartext['query_status'] == "illegal_hash":
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "\nThe provided hash is not valid!\n" + mycolors.reset)
                else:
                    print(mycolors.foreground.red + "\nThe provided hash is not valid!\n" + mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

                                if ("sha1_hash" in y):
                                    if d['sha1_hash']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                                if ("md5_hash" in y):
                                    if d['md5_hash']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                                if ("file_name" in y):
                                    if d['file_name']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                                if ("file_size" in y):
                                    if d['file_size']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                                if ("file_type" in y):
                                    if d['file_type']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                                if ("file_type_mime" in y):
                                    if d['file_type_mime']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                                if ("origin_country" in y):
                                    if d['origin_country']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                                if ("imphash" in y):
                                    if d['imphash']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                                if ("tlsh" in y):
                                    if d['tlsh']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                                if ("comment" in y):
                                    if d['comment']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ncomments: ".ljust(15) + mycolors.reset, end='')
                                        s = d['comment'].split('\n')
                                        for n in range(len(s)):
                                            print("\n".ljust(15) + s[n], end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                                if ("oleinformation" in y):
                                    print(mycolors.foreground.info(cv.bkg) + "\noleinformation: ".ljust(15), end='')
                                    for t in d['oleinformation']:
                                        print(mycolors.reset + t, end=' ')

                                if ("delivery_method" in y):
                                    if d['delivery_method']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ndelivery: ".ljust(15) + mycolors.reset + d['delivery_method'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

                                if ("yara_rules" in y):
                                    if d['yara_rules']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nyara rules: ".ljust(15), end='')
                                        for rule in d['yara_rules']:
                                            if isinstance(rule, dict) and rule.get('rule_name'):
                                                print(mycolors.reset + "\n".ljust(15) + str(rule['rule_name']), end='')

                                if ("file_information" in y):
                                    if (d['file_information'] is not None):
                                        for x in d['file_information']:
                                            if ("context" in x):
                                                if (x['context'] == "twitter"):
                                                    print(mycolors.foreground.yellow + "\nTwitter: ".ljust(15) + mycolors.reset + x['value'], end=' ')
                                                if (x['context'] == "cape"):
                                                    print(mycolors.foreground.yellow + "\nCape: ".ljust(15) + mycolors.reset + x['value'], end=' ')

                                if ("vendor_intel" in y):
                                    if (d['vendor_intel'] is not None):
                                        if ("UnpacMe" in d['vendor_intel']):
                                            if (d['vendor_intel']['UnpacMe']):
                                                print(mycolors.foreground.yellow + "\nUnpacMe: ".ljust(15) + mycolors.reset, end=' ')
                                                filtered_list = []
                                                for j in d['vendor_intel']['UnpacMe']:
                                                    if ("link" in j):
                                                        if j['link'] not in filtered_list:
                                                            filtered_list.append(j['link'])
                                                            for h in filtered_list:
                                                                print('\n'.ljust(15) + h, end=' ')

                                        if ("ANY.RUN" in d['vendor_intel']):
                                            print(mycolors.foreground.yellow + "\nAny.Run: ".ljust(15) + mycolors.reset, end=' ')
                                            for j in d['vendor_intel']['ANY.RUN']:
                                                if ("analysis_url" in j):
                                                    print("\n".ljust(15) + j['analysis_url'], end=' ')

                                        if ("Triage" in d['vendor_intel']):
                                            for j in d['vendor_intel']['Triage']:
                                                if ("link" in j):
                                                    print(mycolors.foreground.yellow + "\n\nTriage: ".ljust(16) + mycolors.reset + d['vendor_intel']['Triage']['link'], end=' ')

                                            if (d['vendor_intel']['Triage']['signatures']):
                                                print(mycolors.foreground.yellow + "\nTriage sigs: ".ljust(15) + mycolors.reset, end='\n')
                                                for m in d['vendor_intel']['Triage']['signatures']:
                                                    if ("signature" in m):
                                                        print(mycolors.reset + "".ljust(14) + m['signature'])

                                        if ("vxCube" in d['vendor_intel']):
                                            for j in d['vendor_intel']['vxCube']:
                                                if ("behaviour" in j):
                                                    print(mycolors.foreground.yellow + "\nDr.Web rules: ".ljust(15) + mycolors.reset)
                                                    for m in d['vendor_intel']['vxCube']['behaviour']:
                                                        if ("rule" in m):
                                                            print(mycolors.reset + "".ljust(14) + m['rule'])

            if (cv.bkg == 0):
                for i in bazaartext.keys():
                    if (i == "data"):
                        if (bazaartext['data'] is not None):
                            for d in bazaartext['data']:
                                y = d.keys()
                                if ("sha256_hash" in y):
                                    if d['sha256_hash']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nsha256_hash: ".ljust(15) + mycolors.reset + d['sha256_hash'], end=' ')

                                if ("sha1_hash" in y):
                                    if d['sha1_hash']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nsha1_hash: ".ljust(15) + mycolors.reset + d['sha1_hash'], end=' ')

                                if ("md5_hash" in y):
                                    if d['md5_hash']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nmd5_hash: ".ljust(15) + mycolors.reset + d['md5_hash'], end=' ')

                                if ("first_seen" in y):
                                    if d['first_seen']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nfirst_seen: ".ljust(15) + mycolors.reset + d['first_seen'], end=' ')

                                if ("last_seen" in y):
                                    if d['last_seen']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nlast_seen: ".ljust(15) + mycolors.reset + d['last_seen'], end=' ')

                                if ("file_name" in y):
                                    if d['file_name']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nfile_name: ".ljust(15) + mycolors.reset + d['file_name'], end=' ')

                                if ("file_size" in y):
                                    if d['file_size']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nfile_size: ".ljust(15) + mycolors.reset + str(d['file_size']) + " bytes", end=' ')

                                if ("file_type" in y):
                                    if d['file_type']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nfile_type: ".ljust(15) + mycolors.reset + str(d['file_type']), end=' ')

                                if ("file_type_mime" in y):
                                    if d['file_type_mime']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nmime_type: ".ljust(15) + mycolors.reset + str(d['file_type_mime']), end=' ')
                                if ("origin_country" in y):
                                    if d['origin_country']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ncountry: ".ljust(15) + mycolors.reset + d['origin_country'], end=' ')

                                if ("imphash" in y):
                                    if d['imphash']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nimphash: ".ljust(15) + mycolors.reset + d['imphash'], end=' ')

                                if ("tlsh" in y):
                                    if d['tlsh']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ntlsh: ".ljust(15) + mycolors.reset + d['tlsh'], end=' ')

                                if ("comment" in y):
                                    if d['comment']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ncomments: ".ljust(15) + mycolors.reset, end='')
                                        s = d['comment'].split('\n')
                                        for n in range(len(s)):
                                            print("\n".ljust(15) + s[n], end=' ')

                                if ("reporter" in y):
                                    if d['reporter']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nreporter: ".ljust(15) + mycolors.reset + d['reporter'], end=' ')

                                if ("oleinformation" in y):
                                    print(mycolors.foreground.info(cv.bkg) + "\noleinformation: ".ljust(15), end='')
                                    for t in d['oleinformation']:
                                        print(mycolors.reset + t, end=' ')

                                if ("delivery_method" in y):
                                    if d['delivery_method']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ndelivery: ".ljust(15) + mycolors.reset + d['delivery_method'], end=' ')

                                if ("tags" in y):
                                    if d['tags']:
                                        print(mycolors.foreground.info(cv.bkg) + "\ntags: ".ljust(15), end='')
                                        for t in d['tags']:
                                            print(mycolors.reset + t, end=' ')

                                if ("yara_rules" in y):
                                    if d['yara_rules']:
                                        print(mycolors.foreground.info(cv.bkg) + "\nyara rules: ".ljust(15), end='')
                                        for rule in d['yara_rules']:
                                            if isinstance(rule, dict) and rule.get('rule_name'):
                                                print(mycolors.reset + "\n".ljust(15) + str(rule['rule_name']), end='')

                                if ("file_information" in y):
                                    if (d['file_information'] is not None):
                                        for x in d['file_information']:
                                            if ("context" in x):
                                                if (x['context'] == "twitter"):
                                                    print(mycolors.foreground.red + "\nTwitter: ".ljust(15) + mycolors.reset + x['value'], end=' ')
                                                if (x['context'] == "cape"):
                                                    print(mycolors.foreground.red + "\nCape: ".ljust(15) + mycolors.reset + x['value'], end=' ')

                                if ("vendor_intel" in y):
                                    if (d['vendor_intel'] is not None):
                                        if ("UnpacMe" in d['vendor_intel']):
                                            if (d['vendor_intel']['UnpacMe']):
                                                print(mycolors.foreground.red + "\nUnpacMe: ".ljust(15) + mycolors.reset, end=' ')
                                                filtered_list = []
                                                for j in d['vendor_intel']['UnpacMe']:
                                                    if ("link" in j):
                                                        if j['link'] not in filtered_list:
                                                            filtered_list.append(j['link'])
                                                            for h in filtered_list:
                                                                print('\n'.ljust(15) + h, end=' ')

                                        if ("ANY.RUN" in d['vendor_intel']):
                                            print(mycolors.foreground.red + "\nAny.Run: ".ljust(15) + mycolors.reset, end=' ')
                                            for j in d['vendor_intel']['ANY.RUN']:
                                                if ("analysis_url" in j):
                                                    print("\n".ljust(15) + j['analysis_url'], end=' ')

                                        if ("Triage" in d['vendor_intel']):
                                            for j in d['vendor_intel']['Triage']:
                                                if ("link" in j):
                                                    print(mycolors.foreground.red + "\n\nTriage: ".ljust(16) + mycolors.reset + d['vendor_intel']['Triage']['link'], end=' ')

                                            if (d['vendor_intel']['Triage']['signatures']):
                                                print(mycolors.foreground.red + "\nTriage sigs: ".ljust(15) + mycolors.reset, end='\n')
                                                for m in d['vendor_intel']['Triage']['signatures']:
                                                    if ("signature" in m):
                                                        print(mycolors.reset + "".ljust(14) + m['signature'])

                                        if ("vxCube" in d['vendor_intel']):
                                            for j in d['vendor_intel']['vxCube']:
                                                if ("behaviour" in j):
                                                    print(mycolors.foreground.red + "\nDr.Web rules: ".ljust(15) + mycolors.reset)
                                                    for m in d['vendor_intel']['vxCube']['behaviour']:
                                                        if ("rule" in m):
                                                            print(mycolors.reset + "".ljust(14) + m['rule'])

            printr()
            return True

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'MalwareBazaar'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            else:
                print((mycolors.foreground.lightred + "\nError while connecting to Malware Bazaar!\n"))
            printr()

    def _batch_widths(self, hashes, filenames=None):
        widths = {}
        keys = []
        if filenames is not None:
            widths['filename'] = column("Filename", filenames, cap=BATCH_COL_FILENAME,
                                        gutter=BATCH_GUTTER)
            keys.append('filename')
        widths['hash'] = column("Hash", hashes, gutter=BATCH_GUTTER)
        widths['type'] = max(len("Type"), BATCH_COL_TYPE) + BATCH_GUTTER
        widths['signature'] = max(len("Signature"), BATCH_COL_SIGNATURE) + BATCH_GUTTER
        widths['tags'] = max(len("Tags"), BATCH_COL_TAGS)
        keys.extend(['hash', 'type', 'signature', 'tags'])
        widths['total'] = sum(widths[key] for key in keys)
        widths['keys'] = keys
        return widths

    def _print_batch_header(self, widths):
        structure = mycolors.foreground.neutral(cv.bkg)
        headers = {'filename': "Filename", 'hash': "Hash", 'type': "Type",
                   'signature': "Signature", 'tags': "Tags"}
        print()
        print(structure
              + "".join(pad(headers[key], widths[key]) for key in widths['keys'])
              + mycolors.reset)
        print(structure + (widths['total'] * '-') + mycolors.reset)

    def _print_batch_row(self, widths, hash_value, file_type, signature, tags, filename=None):
        line = ''
        if 'filename' in widths['keys']:
            line = (mycolors.foreground.info(cv.bkg)
                    + pad(fit(filename, widths['filename'] - BATCH_GUTTER), widths['filename']))
        print(
            line
            + mycolors.foreground.accent(cv.bkg) + pad(hash_value, widths['hash'])
            + mycolors.foreground.ok(cv.bkg) + pad(fit(file_type or 'n/a', widths['type'] - BATCH_GUTTER), widths['type'])
            + mycolors.foreground.error(cv.bkg) + pad(fit(signature or 'n/a', widths['signature'] - BATCH_GUTTER), widths['signature'])
            + mycolors.foreground.warning(cv.bkg) + fit(tags or 'n/a', widths['tags'])
            + mycolors.reset
        )

    def _print_batch_summary(self, widths, checked, found, failed):
        structure = mycolors.foreground.neutral(cv.bkg)
        counts = "%d hash(es) checked: %d found, %d not found" % (checked, found, checked - found - failed)
        if failed:
            counts = counts + ", %d not checked" % failed
        print()
        print(bullet(counts + ".", widths['total'], structure))
        if found < checked:
            print(bullet("not found only means the sample is unknown to MalwareBazaar. It is not a "
                         "verdict that the file is clean.", widths['total'], structure))
        if found:
            print(bullet("Tags shows at most the first %d MalwareBazaar tags for a sample; list "
                         "every sample carrying one of them with -b 2." % BATCH_MAX_TAGS,
                         widths['total'], structure))

    def bazaar_batchcheck(self, filename):
        bazaar = 'https://mb-api.abuse.ch/api/v1/'

        self.requestBAZAARAPI()

        if not os.path.isfile(filename):
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + "\nFile not found: %s\n" % filename)
            else:
                print(mycolors.foreground.red + "\nFile not found: %s\n" % filename)
            printr()
            return

        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                hashes = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + "\nError reading file: %s (%s)\n" % (filename, str(e)))
            else:
                print(mycolors.foreground.red + "\nError reading file: %s (%s)\n" % (filename, str(e)))
            printr()
            return

        widths = self._batch_widths(hashes)
        self._print_batch_header(widths)

        requestsession = create_session()
        requestsession.headers.update({'accept': 'application/json'})
        requestsession.headers.update({'Auth-Key': self.BAZAARAPI})

        found = 0
        failed = 0

        for h in hashes:
            try:
                params = {'query': 'get_info', 'hash': h}
                response = requestsession.post(bazaar, data=params, timeout=60)
                bazaartext = strip_json_escapes(json.loads(response.text))
                add_records('bazaar', 'bazaar_batchcheck', bazaartext)

                file_type = ''
                signature = ''
                tags = ''

                if bazaartext.get('query_status') == 'ok' and bazaartext.get('data'):
                    found = found + 1
                    sample = bazaartext['data'][0]
                    file_type = str(sample.get('file_type', '')) if sample.get('file_type') else ''
                    signature = str(sample.get('signature', '')) if sample.get('signature') else ''
                    tags_list = sample.get('tags', [])
                    tags = ', '.join(tags_list[:BATCH_MAX_TAGS]) if tags_list else ''

                self._print_batch_row(widths, h, file_type, signature, tags)

            except Exception as e:
                failed = failed + 1
                print(mycolors.foreground.error(cv.bkg)
                      + pad(h, widths['hash']) + "error: %s" % str(e) + mycolors.reset)

        self._print_batch_summary(widths, len(hashes), found, failed)

        printr()

    def bazaar_dircheck(self, directory):
        bazaar = 'https://mb-api.abuse.ch/api/v1/'

        self.requestBAZAARAPI()

        if not os.path.isabs(directory):
            directory = os.path.abspath(directory)

        if not os.path.isdir(directory):
            if (cv.bkg == 1):
                print(mycolors.foreground.lightred + "\nDirectory not found: %s\n" % directory)
            else:
                print(mycolors.foreground.red + "\nDirectory not found: %s\n" % directory)
            printr()
            return

        files = []
        for filen in os.listdir(directory):
            filepath = os.path.join(directory, filen)
            if os.path.isfile(filepath):
                try:
                    h = sha256hash(filepath)
                    files.append((filen, h))
                except Exception:
                    pass

        if not files:
            print(mycolors.foreground.error(cv.bkg) + "\nNo files found in directory.\n" + mycolors.reset)
            printr()
            return

        widths = self._batch_widths([h for _f, h in files], filenames=[f for f, _h in files])
        self._print_batch_header(widths)

        requestsession = create_session()
        requestsession.headers.update({'accept': 'application/json'})
        requestsession.headers.update({'Auth-Key': self.BAZAARAPI})

        found = 0
        failed = 0

        for fname, h in files:
            try:
                params = {'query': 'get_info', 'hash': h}
                response = requestsession.post(bazaar, data=params, timeout=60)
                bazaartext = strip_json_escapes(json.loads(response.text))
                add_records('bazaar', 'bazaar_dircheck', bazaartext)

                file_type = ''
                signature = ''
                tags = ''

                if bazaartext.get('query_status') == 'ok' and bazaartext.get('data'):
                    found = found + 1
                    sample = bazaartext['data'][0]
                    file_type = str(sample.get('file_type', '')) if sample.get('file_type') else ''
                    signature = str(sample.get('signature', '')) if sample.get('signature') else ''
                    tags_list = sample.get('tags', [])
                    tags = ', '.join(tags_list[:BATCH_MAX_TAGS]) if tags_list else ''

                self._print_batch_row(widths, h, file_type, signature, tags, filename=fname)

            except Exception as e:
                failed = failed + 1
                print(mycolors.foreground.error(cv.bkg)
                      + pad(fit(fname, widths['filename'] - BATCH_GUTTER), widths['filename'])
                      + "error: %s" % str(e) + mycolors.reset)

        self._print_batch_summary(widths, len(files), found, failed)

        printr()

    def bazaar_yara(self, bazaarx, limit=YARA_LIMIT_DEFAULT):
        bazaar = BazaarExtractor.urlbazaar

        self.requestBAZAARAPI()

        try:
            requested = int(limit)
        except (TypeError, ValueError):
            requested = YARA_LIMIT_DEFAULT

        clamped = max(YARA_LIMIT_MIN, min(YARA_LIMIT_MAX, requested))

        if is_text_output():
            print("\n")
            print(mycolors.reset + "MALWARE BAZAAR YARA REPORT".center(YARA_TABLE_WIDTH))
            print(mycolors.foreground.neutral(cv.bkg) + (YARA_TABLE_WIDTH * '-') + mycolors.reset)

            if clamped != requested:
                print(mycolors.foreground.error(cv.bkg) + "\nThe informed limit (%d) is out of range and was clamped to %d (valid range: %d-%d).\n" % (requested, clamped, YARA_LIMIT_MIN, YARA_LIMIT_MAX) + mycolors.reset)

        try:
            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_yarainfo', 'yara_rule': bazaarx, 'limit': clamped}
            bazaarresponse = requestsession.post(bazaar, data=params, timeout=60)
            bazaartext = strip_json_escapes(json.loads(bazaarresponse.text))
        except ValueError:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError while connecting to Malware Bazaar!\n" + mycolors.reset)
            printr()
            return
        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError while connecting to Malware Bazaar: %s\n" % str(e) + mycolors.reset)
            printr()
            return

        status = bazaartext.get('query_status', '') if isinstance(bazaartext, dict) else ''

        if status != 'ok':
            messages = {
                'no_results': "Your query yield no results!",
                'yara_rule_not_found': "The provided YARA rule name was not found!",
                'illegal_yara_rule': "The provided YARA rule name is not valid!",
                'no_yara_rule_provided': "You didn't provide a YARA rule name!",
                'illegal_limit': "The provided limit is not valid!",
                'illegal_parameter': "The query was refused because of an illegal parameter!",
                'unauthenticated': "Your Malware Bazaar Auth-Key was refused!",
                'http_post_expected': "The Malware Bazaar API expects a POST request!"
            }
            message = messages.get(status, "The Malware Bazaar API returned an unexpected status: %s" % (status if status else 'unknown'))
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\n" + message + "\n" + mycolors.reset)
            printr()
            return

        data = bazaartext.get('data') or []

        if not data:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nYour query yield no results!\n" + mycolors.reset)
            printr()
            return

        if is_text_output():
            structure = mycolors.foreground.neutral(cv.bkg)
            print("")
            print(structure + "Sha256 Hash".ljust(COL_YARA_HASH) + "File Name".ljust(COL_YARA_FILENAME) + "Type".ljust(COL_YARA_TYPE) + "Signature".ljust(COL_YARA_SIGNATURE) + "First Seen")
            print(structure + (YARA_TABLE_WIDTH * '-') + mycolors.reset)

        for d in data:
            if not isinstance(d, dict):
                continue

            sha256_hash = str(d.get('sha256_hash') or '')[:64]
            file_name = str(d.get('file_name') or '')
            file_type = str(d.get('file_type') or '')
            signature = str(d.get('signature') or '')
            first_seen = str(d.get('first_seen') or '')
            tags = d.get('tags')

            record = {
                'yara_rule': bazaarx,
                'sha256_hash': sha256_hash,
                'sha1_hash': str(d.get('sha1_hash') or ''),
                'md5_hash': str(d.get('md5_hash') or ''),
                'file_name': file_name,
                'file_size': d.get('file_size', ''),
                'file_type': file_type,
                'file_type_mime': str(d.get('file_type_mime') or ''),
                'file_format': str(d.get('file_format') or ''),
                'file_arch': str(d.get('file_arch') or ''),
                'signature': signature,
                'reporter': str(d.get('reporter') or ''),
                'imphash': str(d.get('imphash') or ''),
                'tlsh': str(d.get('tlsh') or ''),
                'ssdeep': str(d.get('ssdeep') or ''),
                'first_seen': first_seen,
                'last_seen': str(d.get('last_seen') or ''),
                'tags': ', '.join(str(t) for t in tags) if isinstance(tags, list) else str(tags or '')
            }
            collector.add(record)

            if is_text_output():
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + pad(sha256_hash, COL_YARA_HASH), end='')
                    print(mycolors.foreground.lightgreen + pad(_ellipsis(file_name, COL_YARA_FILENAME - 2), COL_YARA_FILENAME), end='')
                    print(mycolors.foreground.lightcyan + pad(_ellipsis(file_type, COL_YARA_TYPE - 2), COL_YARA_TYPE), end='')
                    print(mycolors.foreground.lightred + pad(_ellipsis(signature, COL_YARA_SIGNATURE - 2), COL_YARA_SIGNATURE), end='')
                    print(mycolors.foreground.pink + _ellipsis(first_seen, COL_YARA_FIRSTSEEN))
                else:
                    print(mycolors.foreground.blue + pad(sha256_hash, COL_YARA_HASH), end='')
                    print(mycolors.foreground.blue + pad(_ellipsis(file_name, COL_YARA_FILENAME - 2), COL_YARA_FILENAME), end='')
                    print(mycolors.foreground.blue + pad(_ellipsis(file_type, COL_YARA_TYPE - 2), COL_YARA_TYPE), end='')
                    print(mycolors.foreground.red + pad(_ellipsis(signature, COL_YARA_SIGNATURE - 2), COL_YARA_SIGNATURE), end='')
                    print(mycolors.foreground.purple + _ellipsis(first_seen, COL_YARA_FIRSTSEEN))

        if is_text_output():
            print("")
            print(bullet("%d sample(s) matched the YARA rule '%s' (limit: %d)."
                         % (len(data), bazaarx, clamped), YARA_TABLE_WIDTH))

        printr()

    def bazaar_yaradownload(self, force=False):
        self.requestBAZAARAPI()
        outputpath = os.path.join(cv.output_dir, YARAIFY_RULES_FILENAME)

        if is_text_output():
            print("\n")
            print(report_header("YARAIFY RULESET DOWNLOAD", REPORT_WIDTH))

        if not force and os.path.isfile(outputpath):
            try:
                age = int(time.time() - os.path.getmtime(outputpath))
            except OSError:
                age = YARAIFY_REFRESH_INTERVAL

            if age < YARAIFY_REFRESH_INTERVAL:
                try:
                    localsize = os.path.getsize(outputpath)
                except OSError:
                    localsize = 0

                collector.add({
                    'ruleset_url': YARAIFY_RULES_URL,
                    'ruleset_path': outputpath,
                    'ruleset_size': localsize,
                    'downloaded': False
                })

                if is_text_output():
                    print(mycolors.foreground.success(cv.bkg) + "\nThe YARAify ruleset is regenerated every %d seconds and the local copy is only %d second(s) old.\nReusing: %s\n" % (YARAIFY_REFRESH_INTERVAL, age, outputpath) + mycolors.reset)

                printr()
                return outputpath

        written = 0

        try:
            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/zip'})
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            response = requestsession.get(YARAIFY_RULES_URL, allow_redirects=False, stream=True, timeout=120)

            if response.status_code in (301, 302, 303, 307, 308):
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nThe YARAify ruleset endpoint redirected to %s. The abuse.ch Auth-Key was most likely refused.\n" % response.headers.get('Location', 'an unknown location') + mycolors.reset)
                printr()
                return None

            if response.status_code in (401, 403):
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nThe YARAify ruleset download was denied (HTTP %d). An abuse.ch Auth-Key might be required for this endpoint.\n" % response.status_code + mycolors.reset)
                printr()
                return None

            if response.status_code != 200:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nThe YARAify ruleset could not be downloaded (HTTP %d).\n" % response.status_code + mycolors.reset)
                printr()
                return None

            toolarge = False

            with open(outputpath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        written += len(chunk)
                        if written > MAX_RULESET_DOWNLOAD_SIZE:
                            toolarge = True
                            break
                        f.write(chunk)

            if toolarge:
                try:
                    os.remove(outputpath)
                except OSError:
                    pass
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nError: Ruleset too large (>%dMB). Download aborted.\n" % (MAX_RULESET_DOWNLOAD_SIZE // (1024 * 1024)) + mycolors.reset)
                printr()
                return None

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError while downloading the YARAify ruleset: %s\n" % str(e) + mycolors.reset)
            printr()
            return None

        if written == 0 or not zipfile.is_zipfile(outputpath):
            try:
                os.remove(outputpath)
            except OSError:
                pass
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nThe downloaded YARAify ruleset is empty or is not a valid zip archive.\n" + mycolors.reset)
            printr()
            return None

        collector.add({
            'ruleset_url': YARAIFY_RULES_URL,
            'ruleset_path': outputpath,
            'ruleset_size': written,
            'downloaded': True
        })

        if is_text_output():
            print(mycolors.foreground.success(cv.bkg) + "\nYARAify ruleset (%d bytes) downloaded to: %s\n" % (written, outputpath) + mycolors.reset)

        printr()
        return outputpath

    def bazaar_yaraextract(self, zippath=None, destdir=None):
        if not zippath:
            zippath = os.path.join(cv.output_dir, YARAIFY_RULES_FILENAME)

        if not destdir:
            destdir = os.path.join(cv.output_dir, YARAIFY_RULES_DIRNAME)

        if is_text_output():
            print("\n")
            print(report_header("YARAIFY RULESET EXTRACTION", REPORT_WIDTH))

        if not os.path.isfile(zippath):
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nRuleset archive not found: %s\n" % zippath + mycolors.reset)
            printr()
            return None

        if not zipfile.is_zipfile(zippath):
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nNot a valid zip archive: %s\n" % zippath + mycolors.reset)
            printr()
            return None

        try:
            os.makedirs(destdir, exist_ok=True)
        except OSError as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nThe rules directory could not be created: %s (%s)\n" % (destdir, str(e)) + mycolors.reset)
            printr()
            return None

        destroot = os.path.realpath(destdir)

        extracted = 0
        totalbytes = 0
        inspected = 0
        skippednotrule = 0
        skippeddirs = 0
        rejected = []

        try:
            with zipfile.ZipFile(zippath, 'r') as zf:
                for info in zf.infolist():
                    inspected += 1

                    if inspected > MAX_RULESET_ENTRIES:
                        rejected.append(('<archive>', 'archive entry cap of %d reached' % MAX_RULESET_ENTRIES))
                        break

                    name = strip_terminal_escapes(info.filename) or '<unprintable name>'

                    if info.is_dir() or info.filename.endswith('/') or info.filename.endswith('\\'):
                        skippeddirs += 1
                        continue

                    if stat.S_ISLNK(info.external_attr >> 16):
                        rejected.append((name, 'symlink entry'))
                        continue

                    if _unsafe_member_name(info.filename):
                        rejected.append((name, 'absolute path, path traversal or control character'))
                        continue

                    if not info.filename.lower().endswith(YARA_RULE_EXTENSIONS):
                        skippednotrule += 1
                        continue

                    target = os.path.realpath(os.path.join(destroot, *_member_parts(info.filename)))

                    if not _inside_directory(destroot, target):
                        rejected.append((name, 'resolves outside the rules directory'))
                        continue

                    if extracted >= MAX_RULESET_MEMBERS:
                        rejected.append((name, 'member cap of %d reached' % MAX_RULESET_MEMBERS))
                        break

                    if info.file_size > MAX_RULESET_MEMBER_BYTES:
                        rejected.append((name, 'declared size of %d bytes exceeds the per-member cap of %d bytes' % (info.file_size, MAX_RULESET_MEMBER_BYTES)))
                        continue

                    if totalbytes + info.file_size > MAX_RULESET_TOTAL_BYTES:
                        rejected.append((name, 'total uncompressed cap of %d bytes reached' % MAX_RULESET_TOTAL_BYTES))
                        break

                    allowed = min(info.file_size, MAX_RULESET_MEMBER_BYTES)
                    parent = os.path.dirname(target)

                    if parent and not os.path.isdir(parent):
                        try:
                            os.makedirs(parent, exist_ok=True)
                        except OSError as e:
                            rejected.append((name, 'directory error: %s' % str(e)))
                            continue

                    memberbytes = 0
                    overflow = False

                    try:
                        with zf.open(info, 'r') as src, open(target, 'wb') as dst:
                            while True:
                                chunk = src.read(65536)
                                if not chunk:
                                    break
                                memberbytes += len(chunk)
                                if memberbytes > allowed:
                                    overflow = True
                                    break
                                dst.write(chunk)
                    except Exception as e:
                        rejected.append((name, 'read error: %s' % str(e)))
                        try:
                            os.remove(target)
                        except OSError:
                            pass
                        continue

                    if overflow:
                        rejected.append((name, 'decompressed size exceeds the declared size of %d bytes' % info.file_size))
                        try:
                            os.remove(target)
                        except OSError:
                            pass
                        continue

                    extracted += 1
                    totalbytes += memberbytes

        except zipfile.BadZipFile:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nThe ruleset archive is corrupted: %s\n" % zippath + mycolors.reset)
            printr()
            return None
        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nError while extracting the ruleset archive: %s\n" % str(e) + mycolors.reset)
            printr()
            return None

        collector.add({
            'ruleset_archive': zippath,
            'rules_directory': destroot,
            'entries_inspected': inspected,
            'extracted': extracted,
            'extracted_bytes': totalbytes,
            'skipped_not_rule': skippednotrule,
            'skipped_directories': skippeddirs,
            'rejected': len(rejected),
            'rejected_details': '; '.join('%s (%s)' % (n, r) for n, r in rejected[:20])
        })

        if is_text_output():
            fields = {
                'Archive': zippath,
                'Rules Directory': destroot,
                'Entries Inspected': str(inspected),
                'Extracted': '%d rule file(s)' % extracted,
                'Extracted Size': '%d bytes' % totalbytes,
                'Skipped (not a rule)': str(skippednotrule),
                'Skipped (directory)': str(skippeddirs),
                'Rejected (unsafe)': str(len(rejected))
            }

            COLSIZE = max(len(f) for f in fields.keys()) + 3

            print()
            for field, value in fields.items():
                print(mycolors.foreground.info(cv.bkg) + ("%s:" % field).ljust(COLSIZE) + mycolors.reset + value)

            if rejected:
                print()
                print(mycolors.foreground.error(cv.bkg) + "Rejected entries:" + mycolors.reset)
                for name, reason in rejected[:20]:
                    print("  " + _ellipsis(name, 58).ljust(60) + reason)
                if len(rejected) > 20:
                    print("  ... and %d more" % (len(rejected) - 20))

            if extracted == 0:
                print()
                print(mycolors.foreground.error(cv.bkg) + "No YARA rule file was extracted from the archive." + mycolors.reset)

        printr()

        if extracted == 0:
            return None

        return destroot

    @cached("bazaar_hash")
    def _raw_hash_info(self, hash_value):
        try:
            bazaar = 'https://mb-api.abuse.ch/api/v1/'
            requestsession = create_session()
            requestsession.headers.update({'Auth-Key': self.BAZAARAPI})
            params = {'query': 'get_info', 'hash': hash_value}
            response = requestsession.post(bazaar, data=params, timeout=60)
            if response.status_code == 200:
                data = strip_json_escapes(response.json())
                if data.get('query_status') == 'ok' and data.get('data'):
                    return data['data'][0]
        except Exception:
            pass
        return None
