import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr, strip_json_escapes, bullet, pad, fit, column, divider, report_header
import json
import requests
import sys
import os
from urllib.parse import quote
from malwoverview.utils.session import create_session
from malwoverview.utils.config import redact_secret
from malwoverview.utils.output import collector, is_text_output

COL_TYPE = 40
COL_SAMPLES = 30
COL_GUTTER = 2
TYPES_TABLE_WIDTH = COL_TYPE + COL_SAMPLES

LIST_SHA256_SAMPLE = '0' * 64
LIST_MD5_SAMPLE = '0' * 32
LIST_COL_TYPE_MAX = COL_TYPE


class MalshareExtractor():
    urlmalshare = 'https://malshare.com/api.php?api_key='

    def __init__(self, MALSHAREAPI):
        self.MALSHAREAPI = MALSHAREAPI

    def requestMALSHAREAPI(self):
        if (self.MALSHAREAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get/submit information from/to Malshare, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Malshare API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def malsharedown(self, filehash):
        if len(filehash) not in [32, 40, 64]:
            return False

        urlmalshare = MalshareExtractor.urlmalshare
        malresponse3 = ''
        resource = ''

        self.requestMALSHAREAPI()

        try:
            resource = filehash
            requestsession3 = create_session()
            finalurl3 = ''.join([
                urlmalshare, self.MALSHAREAPI,
                '&action=getfile&hash=', resource
            ])

            malresponse3 = requestsession3.get(
                url=finalurl3,
                stream=True,
                timeout=60
            )

            MAX_DOWNLOAD_SIZE = 500 * 1024 * 1024
            content = bytearray()
            for chunk in malresponse3.iter_content(chunk_size=8192):
                if chunk:
                    content += chunk
                    if len(content) > MAX_DOWNLOAD_SIZE:
                        print(mycolors.foreground.red + "\nError: File too large (>500MB). Download aborted.\n" + mycolors.reset)
                        return False

            if (b'Sample not found by hash' in content) or malresponse3.status_code != 200 or not content:
                if (cv.bkg == 1):
                    print((mycolors.foreground.lightred + "\nSample not found by the provided hash.\n" + mycolors.reset))
                else:
                    print((mycolors.foreground.red + "\nSample not found by the provided hash.\n" + mycolors.reset))
                printr()
                return False
            else:
                safe_filename = os.path.basename(resource)
                outputpath = os.path.join(cv.output_dir, safe_filename)
                with open(outputpath, 'wb') as f:
                    f.write(content)
                    collector.add({'service': 'malshare', 'query_type': 'malsharedown', 'query': filehash, 'file': outputpath, 'size': os.path.getsize(outputpath)})

                print("\n")
                print((mycolors.reset + f"Sample downloaded to: {outputpath}"))
                printr()
        except (ValueError, requests.exceptions.RequestException) as e:
            print(redact_secret(e, self.MALSHAREAPI))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malshare.com!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malshare.com!\n"))
            printr()
            return False
        except (BrokenPipeError, IOError):
            print(mycolors.reset, file=sys.stderr)
            return False

    TYPE_MAP = {
        2: 'PE32',
        3: 'ELF',
        4: 'Java',
        5: 'PDF',
    }

    MAX_TYPE_LEN = 64

    def malsharetypes(self):
        urlmalshare = MalshareExtractor.urlmalshare

        self.requestMALSHAREAPI()

        try:
            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})
            finalurl = ''.join([urlmalshare, self.MALSHAREAPI, '&action=gettypes'])
            malresponse = requestsession.get(url=finalurl)
            maltext = strip_json_escapes(json.loads(malresponse.text))
        except (ValueError, requests.exceptions.RequestException) as e:
            print(redact_secret(e, self.MALSHAREAPI))
            print(mycolors.foreground.error(cv.bkg) + "Error while connecting to Malshare.com!\n")
            printr()
            return False

        if not maltext:
            print(mycolors.foreground.error(cv.bkg) + "\nMalshare returned no file types.\n" + mycolors.reset)
            return False

        if isinstance(maltext, dict):
            entries = sorted(maltext.items(), key=lambda kv: str(kv[0]).lower())
        else:
            entries = [(str(item), '') for item in maltext]

        structure = mycolors.foreground.neutral(cv.bkg)

        if is_text_output():
            print("\n")
            print(mycolors.reset + "MALSHARE FILE TYPES (LAST 24 HOURS)".center(TYPES_TABLE_WIDTH))
            print(structure + (TYPES_TABLE_WIDTH * '-') + mycolors.reset)
            print(
                structure
                + "File Type".ljust(COL_TYPE) + "Samples"
                + mycolors.reset
            )
            print(structure + (TYPES_TABLE_WIDTH * '-') + mycolors.reset)

        for name, count in entries:
            collector.add({'file_type': str(name), 'count': str(count)})
            if is_text_output():
                print(
                    mycolors.foreground.info(cv.bkg)
                    + pad(fit(str(name), COL_TYPE - COL_GUTTER), COL_TYPE)
                    + mycolors.foreground.ok(cv.bkg) + str(count)
                    + mycolors.reset
                )

        if is_text_output():
            print()
            print(bullet("Use -l 8 -L <file type> to list the hashes of one of these types.",
                         TYPES_TABLE_WIDTH, structure))
        printr()
        return True

    def malsharetypelist(self, filetype):
        if not filetype:
            print(mycolors.foreground.error(cv.bkg) + "\nA file type is required. List the available types with -l 6.\n" + mycolors.reset)
            return False
        filetype = filetype.strip()
        if len(filetype) > MalshareExtractor.MAX_TYPE_LEN:
            print(mycolors.foreground.error(cv.bkg) + "\nFile type is too long.\n" + mycolors.reset)
            return False
        return self._list_by_type(filetype)

    def malsharelastlist(self, typex):
        self.requestMALSHAREAPI()
        filetype = MalshareExtractor.TYPE_MAP.get(typex, 'all')
        return self._list_by_type(filetype)

    def _list_by_type(self, filetype):
        urlmalshare = MalshareExtractor.urlmalshare
        maltext = ''
        malresponse = ''

        self.requestMALSHAREAPI()

        try:
            requestsession = create_session()
            requestsession.headers.update({'accept': 'application/json'})

            typed = (filetype != "all")
            if typed:
                finalurl = ''.join([
                    urlmalshare, self.MALSHAREAPI,
                    '&action=type&type=', quote(filetype, safe='')
                ])
            else:
                finalurl = ''.join([urlmalshare, self.MALSHAREAPI, '&action=getlist'])

            malresponse = requestsession.get(url=finalurl)
            maltext = strip_json_escapes(json.loads(malresponse.text))

            if isinstance(maltext, dict) and maltext.get('ERROR'):
                print(mycolors.foreground.error(cv.bkg) + "\nMalshare error: " + str(maltext['ERROR']) + "\n" + mycolors.reset)
                return False

            if maltext:
                widths = [column("SHA256", [LIST_SHA256_SAMPLE], gutter=COL_GUTTER),
                          column("MD5", [LIST_MD5_SAMPLE], gutter=COL_GUTTER)]
                headers = ["SHA256", "MD5"]
                if typed:
                    widths.append(column("Type", [filetype], cap=LIST_COL_TYPE_MAX,
                                         gutter=COL_GUTTER))
                    headers.append("Type")
                table_width = sum(widths)

                neutral = mycolors.foreground.neutral(cv.bkg)
                shacolor = mycolors.foreground.accent(cv.bkg)
                md5color = mycolors.foreground.info(cv.bkg)
                typecolor = mycolors.foreground.warning(cv.bkg)

                if is_text_output():
                    title = "MALSHARE SAMPLE LIST" if not typed else "MALSHARE SAMPLES BY TYPE"
                    print()
                    print(report_header(title, table_width))
                    print(neutral + ''.join(pad(h, w) for h, w in zip(headers, widths))
                          + mycolors.reset)
                    print(divider(table_width))

                shown = 0
                try:
                    for entry in maltext:
                        if not isinstance(entry, dict) or not entry.get('sha256'):
                            continue
                        sha256 = str(entry.get('sha256', '')) or 'n/a'
                        md5 = str(entry.get('md5', '')) or 'n/a'
                        collector.add({
                            'sha256': sha256,
                            'md5': md5,
                            'file_type': filetype,
                        })
                        if not is_text_output():
                            continue
                        row = (shacolor + pad(sha256, widths[0])
                               + md5color + pad(md5, widths[1]))
                        if typed:
                            row = row + typecolor + fit(filetype, widths[2])
                        print(row + mycolors.reset)
                        shown = shown + 1
                except KeyError:
                    pass
                except (BrokenPipeError, IOError):
                    print(mycolors.reset, file=sys.stderr)
                    return False

                if is_text_output():
                    print(divider(table_width))
                    print(bullet("%d sample(s) listed." % shown, table_width))
        except (ValueError, requests.exceptions.RequestException) as e:
            print(redact_secret(e, self.MALSHAREAPI))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malshare.com!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malshare.com!\n"))
            printr()
            return False

        return True
