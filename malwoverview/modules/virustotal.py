import malwoverview.modules.configvars as cv
from datetime import datetime
from malwoverview.utils.colors import mycolors, printr, strip_json_escapes, wrap_field, divider, display_width
from malwoverview.utils.hash import sha256hash
from malwoverview.utils.peinfo import ftype, isoverlay, overlaysize, humansize, fileentropy, overextract, list_imports_exports
import geocoder
import validators
import requests
import base64
import textwrap
import json
import time
import re
import os
from urllib.parse import quote
from malwoverview.utils.output import collector, is_text_output, add_records
from malwoverview.utils.session import create_session
from malwoverview.utils.cache import cached
from malwoverview.utils.attack import map_and_display

SIG_REPORT_WIDTH = 120
SIG_LABEL_WIDTH = 15
SIG_SECTION_INDENT = 21
SIG_FIELD_INDENT = 36


class VirusTotalExtractor():
    urlfilevt3 = 'https://www.virustotal.com/api/v3/files'
    urlurlvt3 = 'https://www.virustotal.com/api/v3/urls'
    urlipvt3 = 'https://www.virustotal.com/api/v3/ip_addresses'
    urldomainvt3 = 'https://www.virustotal.com/api/v3/domains'
    AV_LIST = [
        "AlienVault", "BitDefender", "Avira", "Comodo Valkyrie Verdict", "CyRadar",
        "Dr.Web", "Emsisoft", "ESET", "Forcepoint ThreatSeeker", "Fortinet", "G-Data",
        "Google Safebrowsing", "Kaspersky", "MalwarePatrol", "OpenPhish", "PhishLabs",
        "Phishtank", "Spamhaus", "Sophos", "Sucuri SiteCheck", "Trustwave", "URLhaus",
        "VX Vault", "Webroot"
    ]
    urlretrohuntvt3 = 'https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs'
    urlhuntrulesetvt3 = 'https://www.virustotal.com/api/v3/intelligence/hunting_rulesets'
    urlhuntnotificationvt3 = 'https://www.virustotal.com/api/v3/intelligence/hunting_notifications'
    urlhuntnotificationfilesvt3 = 'https://www.virustotal.com/api/v3/intelligence/hunting_notification_files'
    HUNT_MAX_RULES_BYTES = 1048576
    HUNT_MAX_RULES = 300
    HUNT_SIZE_NOTE = 'VirusTotal excludes files larger than 100 MB from both Retrohunt and Livehunt scans.'
    RETROHUNT_STATUS = ['starting', 'running', 'aborting', 'aborted', 'finished']
    RETROHUNT_CORPUS = ['main', 'goodware']
    HUNT_MATCH_TYPES = ['file', 'url', 'domain', 'ip']

    def __init__(self, VTAPI):
        self.VTAPI = VTAPI

    def requestVTAPI(self):
        if self.VTAPI == '' or self.VTAPI is None:
            print(mycolors.foreground.error(cv.bkg) + "\nTo be able to get information from VirusTotal, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the VirusTotal API key according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def filechecking_v3(self, ffpname2, showreport, impexp, ovrly):
        if not ffpname2 or not os.path.isfile(ffpname2):
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid file.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid file.\n")
            return False

        targetfile = ffpname2
        mysha256hash = ''
        dname = str(os.path.dirname(targetfile))
        if not os.path.abspath(dname):
            dname = os.path.abspath('.') + "/" + dname

        try:
            mysha256hash = sha256hash(targetfile)

            magictype = ftype(targetfile)
            ovrlsize = ''
            if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                ret_overlay = isoverlay(targetfile)
                if (ret_overlay == "YES"):
                    ovrlsize = humansize(overlaysize(targetfile))
            fent = "%.2f" % fileentropy(targetfile)

            if (showreport == 0):
                self.vthashwork(mysha256hash, showreport)

                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
                        if (ret_overlay == "YES"):
                            print(mycolors.foreground.lightred + "Overlay Size: ".ljust(21) + mycolors.reset + ovrlsize, end='\n')
                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    if (cv.bkg == 0):
                        print(mycolors.foreground.red + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
                        if (ret_overlay == "YES"):
                            print(mycolors.foreground.red + "Overlay Size: ".ljust(21) + mycolors.reset + ovrlsize, end='\n')
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "Entropy: ".ljust(21) + mycolors.reset + fent, end='\n')
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "Entropy: ".ljust(21) + mycolors.reset + fent, end='\n')
            else:
                self.vtreportwork(mysha256hash, 1)

                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
                        if (ret_overlay == "YES"):
                            print(mycolors.foreground.lightred + "Overlay Size: ".ljust(21) + mycolors.reset + ovrlsize, end='\n')
                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    if (cv.bkg == 0):
                        print(mycolors.foreground.red + "Overlay: ".ljust(21) + mycolors.reset + ret_overlay, end='\n')
                        if (ret_overlay == "YES"):
                            print(mycolors.foreground.red + "Overlay Size: ".ljust(21) + mycolors.reset + ovrlsize, end='\n')
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightred + "Entropy: ".ljust(21) + mycolors.reset + fent, end='\n')
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "Entropy: ".ljust(21) + mycolors.reset + fent, end='\n')
            if (impexp == 1):
                list_imports_exports(targetfile)
            if (ovrly == 1):
                overextract(targetfile)
        except (AttributeError, NameError) as e:
            print(e)
            if (cv.bkg == 1):
                print((mycolors.foreground.yellow + "\nAn error has occured while handling the %s file.\n" % targetfile))
                pass
            else:
                print((mycolors.foreground.red + "\nAn error has occured while handling the %s file.\n" % targetfile))
            printr()
            exit(1)

    def vtcheck(self, myhash, showreport):
        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/", quote(myhash, safe='')])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = strip_json_escapes(json.loads(response.text))
            add_records('virustotal', 'vtcheck', vttext)

            if (response.status_code == 404):
                final = " NOT FOUND"
            else:
                attrs = vttext.get('data', {}).get('attributes', {})
                if ('last_analysis_stats' in attrs):
                    malicious = attrs['last_analysis_stats']['malicious']
                    undetected = attrs['last_analysis_stats']['undetected']
                    final = (str(malicious) + "/" + str(malicious + undetected))

            return final
        except ValueError:
            final = '     '
            return final

    def vt_url_ip_domain_report_dark(self, vttext):
        print(mycolors.foreground.lightred + "\n\nAV Report:", end='')

        attrs = vttext.get('data', {}).get('attributes', {})
        if ('last_analysis_results' in attrs):
            ok = "CLEAN"
            if ('AlienVault' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['AlienVault']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + ok, end='')
            if ('BitDefender' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['BitDefender']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Avira' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Avira']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Comodo Valkyrie Verdict' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Comodo Valkyrie Verdict']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + ok, end='')
            if ('CyRadar' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['CyRadar']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Dr.Web' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Dr.Web']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Emsisoft' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Emsisoft']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
            if ('ESET' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['ESET']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Forcepoint ThreatSeeker' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Forcepoint ThreatSeeker']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Fortinet' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Fortinet']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
            if ('G-Data' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['G-Data']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Google Safebrowsing' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Google Safebrowsing']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Kaspersky' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Kaspersky']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
            if ('MalwarePatrol' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['MalwarePatrol']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + ok, end='')
            if ('OpenPhish' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['OpenPhish']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + ok, end='')
            if ('PhishLabs' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['PhishLabs']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Phishtank' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Phishtank']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Spamhaus' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Spamhaus']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Sophos' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Sophos']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Sucuri SiteCheck' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Sucuri SiteCheck']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Trustwave' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Trustwave']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + ok, end='')
            if ('URLhaus' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['URLhaus']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + ok, end='')
            if ('VX Vault' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['VX Vault']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Webroot' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Webroot']['result']
                if (result):
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.lightcyan + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + ok, end='')

    def vt_url_ip_domain_report_light(self, vttext):
        print(mycolors.foreground.red + "\n\nAV Report:", end='')
        attrs = vttext.get('data', {}).get('attributes', {})

        if ('last_analysis_results' in attrs):
            ok = "CLEAN"
            if ('AlienVault' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['AlienVault']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "AlienVault: ".ljust(15) + mycolors.reset + ok, end='')
            if ('BitDefender' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['BitDefender']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Avira' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Avira']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Comodo Valkyrie Verdict' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Comodo Valkyrie Verdict']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Comodo: ".ljust(15) + mycolors.reset + ok, end='')
            if ('CyRadar' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['CyRadar']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "CyRadar: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Dr.Web' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Dr.Web']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Dr.Web: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Emsisoft' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Emsisoft']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
            if ('ESET' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['ESET']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "ESET: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Forcepoint ThreatSeeker' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Forcepoint ThreatSeeker']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Forcepoint: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Fortinet' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Fortinet']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
            if ('G-Data' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['G-Data']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "G-Data: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Google Safebrowsing' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Google Safebrowsing']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Google: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Kaspersky' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Kaspersky']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
            if ('MalwarePatrol' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['MalwarePatrol']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "MalwarePatrol: ".ljust(15) + mycolors.reset + ok, end='')
            if ('OpenPhish' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['OpenPhish']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "OpenPhish: ".ljust(15) + mycolors.reset + ok, end='')
            if ('PhishLabs' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['PhishLabs']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "PhishLabs: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Phishtank' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Phishtank']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Phishtank: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Spamhaus' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Spamhaus']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Spamhaus: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Sophos' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Sophos']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Sucuri SiteCheck' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Sucuri SiteCheck']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Sucuri: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Trustwave' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Trustwave']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Trustwave: ".ljust(15) + mycolors.reset + ok, end='')
            if ('URLhaus' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['URLhaus']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "URLhaus: ".ljust(15) + mycolors.reset + ok, end='')
            if ('VX Vault' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['VX Vault']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "VX Vault: ".ljust(15) + mycolors.reset + ok, end='')
            if ('Webroot' in attrs['last_analysis_results']):
                result = attrs['last_analysis_results']['Webroot']['result']
                if (result):
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + result, end='')
                else:
                    print(mycolors.foreground.blue + "\n".ljust(26) + "Webroot: ".ljust(15) + mycolors.reset + ok, end='')

    def vtdomainwork(self, mydomain):
        if not mydomain or not validators.domain(mydomain):
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid domain.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid domain.\n")
            return False

        url = VirusTotalExtractor.urldomainvt3

        try:
            finalurl = ''.join([url, "/", quote(mydomain, safe='')])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = strip_json_escapes(json.loads(response.text))
            add_records('virustotal', 'vtdomainwork', vttext)

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nDOMAIN NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nDOMAIN NOT FOUND!")
            else:
                attrs = vttext.get('data', {}).get('attributes', {})
                if (cv.bkg == 1):
                    if ('creation_date' in attrs):
                        create_date = attrs['creation_date']
                        print(mycolors.foreground.yellow + "\nCreation Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(create_date)), end='')
                    if ('last_update_date' in attrs):
                        last_update_date = attrs['last_update_date']
                        print(mycolors.foreground.yellow + "\nLast Update Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_update_date)), end='')
                    if ('registrar' in attrs):
                        registrar = attrs['registrar']
                        print(mycolors.foreground.yellow + "\nRegistrar: ".ljust(26) + mycolors.reset + registrar, end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.yellow + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                    if ('whois' in attrs):
                        whois = attrs['whois']
                        print(mycolors.foreground.yellow + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()), width=80)), end=' ')
                    if ('whois_date' in attrs):
                        whois_date = attrs['whois_date']
                        print(mycolors.foreground.yellow + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                    if ('jarm' in attrs):
                        jarm = attrs['jarm']
                        print(mycolors.foreground.lightred + "\n\nJarm: ".ljust(27) + mycolors.reset + str(jarm), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')

                    self.vt_url_ip_domain_report_dark(vttext)

                if (cv.bkg == 0):
                    if ('creation_date' in attrs):
                        create_date = attrs['creation_date']
                        print(mycolors.foreground.green + "\nCreation Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(create_date)), end='')
                    if ('last_update_date' in attrs):
                        last_update_date = attrs['last_update_date']
                        print(mycolors.foreground.green + "\nLast Update Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_update_date)), end='')
                    if ('registrar' in attrs):
                        registrar = attrs['registrar']
                        print(mycolors.foreground.green + "\nRegistrar: ".ljust(26) + mycolors.reset + registrar, end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.green + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                    if ('whois' in attrs):
                        whois = attrs['whois']
                        print(mycolors.foreground.green + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()), width=80)), end=' ')
                    if ('whois_date' in attrs):
                        whois_date = attrs['whois_date']
                        print(mycolors.foreground.green + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                    if ('jarm' in attrs):
                        jarm = attrs['jarm']
                        print(mycolors.foreground.red + "\n\nJarm: ".ljust(27) + mycolors.reset + str(jarm), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.red + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')

                    self.vt_url_ip_domain_report_light(vttext)
        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def _raw_ip_info(self, myip):
        url = VirusTotalExtractor.urlipvt3

        finalurl = ''.join([url, "/", quote(myip, safe='')])
        requestsession = create_session()
        requestsession.headers.update({'x-apikey': self.VTAPI})
        requestsession.headers.update({'content-type': 'application/json'})
        response = requestsession.get(finalurl)
        return response

    def vtipwork(self, myip):
        if not myip:
            return False

        try:
            response = self._raw_ip_info(myip)
            vttext = strip_json_escapes(response.json())
            add_records('virustotal', 'vtipwork', vttext)

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nIP ADDRESS NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nIP ADDRESS NOT FOUND!")
            else:
                attrs = vttext.get('data', {}).get('attributes', {})

                if (cv.bkg == 1):
                    if ('as_owner' in attrs):
                        as_owner = attrs['as_owner']
                        print(mycolors.foreground.yellow + "\nAS Owner: ".ljust(26) + mycolors.reset + as_owner, end='')
                    if ('asn' in attrs):
                        asn = attrs['asn']
                        print(mycolors.foreground.yellow + "\nASN: ".ljust(26) + mycolors.reset + str(asn), end='')
                    if ('whois_date' in attrs):
                        whois_date = attrs['whois_date']
                        print(mycolors.foreground.yellow + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                    if ('whois' in attrs):
                        whois = attrs['whois']
                        print(mycolors.foreground.yellow + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()), width=80)), end=' ')
                    if ('country' in attrs):
                        country = attrs['country']
                        print(mycolors.foreground.lightcyan + "\n\nCountry: ".ljust(27) + mycolors.reset + country, end='')
                    if ('jarm' in attrs):
                        jarm = attrs['jarm']
                        print(mycolors.foreground.lightcyan + "\nJARM: ".ljust(26) + mycolors.reset + str(jarm), end='')
                    if ('network' in attrs):
                        network = attrs['network']
                        print(mycolors.foreground.lightcyan + "\nNetwork: ".ljust(26) + mycolors.reset + str(network), end='')
                    if ('regional_internet_registry' in attrs):
                        rir = attrs['regional_internet_registry']
                        print(mycolors.foreground.lightcyan + "\nR.I.R: ".ljust(26) + mycolors.reset + str(rir), end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.lightred + "\n\nReputation: ".ljust(27) + mycolors.reset + str(reputation), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                    print(mycolors.foreground.lightred + "\nCity: ".ljust(26) + mycolors.reset + str(geocoder.ip(myip).city), end='')

                    self.vt_url_ip_domain_report_dark(vttext)

                if (cv.bkg == 0):
                    if ('as_owner' in attrs):
                        as_owner = attrs['as_owner']
                        print(mycolors.foreground.blue + "\nAS Owner: ".ljust(26) + mycolors.reset + as_owner, end='')
                    if ('asn' in attrs):
                        asn = attrs['asn']
                        print(mycolors.foreground.blue + "\nASN: ".ljust(26) + mycolors.reset + str(asn), end='')
                    if ('whois_date' in attrs):
                        whois_date = attrs['whois_date']
                        print(mycolors.foreground.blue + "\nWhois Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(whois_date)), end='')
                    if ('whois' in attrs):
                        whois = attrs['whois']
                        print(mycolors.foreground.blue + "\nWhois: ".ljust(26) + mycolors.reset + (mycolors.reset + "\n".ljust(26)).join(textwrap.wrap(" ".join(whois.split()), width=80)), end=' ')
                    if ('country' in attrs):
                        country = attrs['country']
                        print(mycolors.foreground.green + "\n\nCountry: ".ljust(27) + mycolors.reset + country, end='')
                    if ('jarm' in attrs):
                        jarm = attrs['jarm']
                        print(mycolors.foreground.green + "\nJARM: ".ljust(26) + mycolors.reset + str(jarm), end='')
                    if ('network' in attrs):
                        network = attrs['network']
                        print(mycolors.foreground.green + "\nNetwork: ".ljust(26) + mycolors.reset + str(network), end='')
                    if ('regional_internet_registry' in attrs):
                        rir = attrs['regional_internet_registry']
                        print(mycolors.foreground.green + "\nR.I.R: ".ljust(26) + mycolors.reset + str(rir), end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.red + "\n\nReputation: ".ljust(27) + mycolors.reset + str(reputation), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.red + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                    print(mycolors.foreground.red + "\nCity: ".ljust(26) + mycolors.reset + str(geocoder.ip(myip).city), end='')

                    self.vt_url_ip_domain_report_light(vttext)

                print("\n")

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtipbatchwork(self, myip):
        try:
            response = self._raw_ip_info(myip)
            vttext = strip_json_escapes(response.json())
            add_records('virustotal', 'vtipbatchwork', vttext)

            if (response.status_code == 404):
                return (False, 'N/A', 'NOT FOUND', 0, 0)

            attrs = vttext.get('data', {}).get('attributes', {})
            country = attrs.get('country', 'N/A')
            as_owner = attrs.get('as_owner', 'N/A')
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) if stats else 0
            return (True, country, as_owner, malicious, total)
        except (ValueError, requests.exceptions.RequestException):
            return (False, 'N/A', 'ERROR', 0, 0)

    def vtipbatchcheck(self, filename, apitype):
        apitype_var = apitype

        try:
            with open(filename, 'r') as fh:
                iplines = fh.readlines()
        except OSError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nThe provided file doesn't exist!\n"))
            else:
                print((mycolors.foreground.red + "\nThe provided file doesn't exist!\n"))
            print(mycolors.reset)
            exit(3)

        ipwidth = max([len("IP Address")] + [len(line.strip()) for line in iplines if line.strip()]) + 2

        print(mycolors.reset)
        print("IP Address".ljust(ipwidth) + "Country".ljust(12) + "AS Owner".ljust(42) + "Detection".ljust(14))
        print('-' * (ipwidth + 68), end="\n\n")

        ipnumber = 0
        for ipitem in iplines:
            myip = ipitem.strip()
            if not myip:
                continue
            ipnumber = ipnumber + 1

            (found, country, as_owner, malicious, total) = self.vtipbatchwork(myip)
            as_owner_short = (as_owner[:38] + '...') if len(as_owner) > 38 else as_owner

            if not found:
                detection = '-'
            else:
                detection = str(malicious) + "/" + str(total)

            if (cv.bkg == 1):
                detcolor = mycolors.foreground.lightred if (found and malicious > 0) else mycolors.foreground.lightgreen
                print(mycolors.foreground.lightcyan + myip.ljust(ipwidth) + mycolors.foreground.yellow + str(country).ljust(12) + mycolors.reset + as_owner_short.ljust(42) + detcolor + detection.ljust(14) + mycolors.reset)
            else:
                detcolor = mycolors.foreground.red if (found and malicious > 0) else mycolors.foreground.green
                print(mycolors.foreground.purple + myip.ljust(ipwidth) + mycolors.foreground.blue + str(country).ljust(12) + mycolors.reset + as_owner_short.ljust(42) + detcolor + detection.ljust(14) + mycolors.reset)

            if (apitype_var == 1):
                if ((ipnumber % 4) == 0):
                    time.sleep(61)

    def vturlwork(self, myurl):
        if not myurl or not validators.url(myurl):
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid URL.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid URL.\n")
            return False

        url = VirusTotalExtractor.urlurlvt3

        try:
            urlid = base64.urlsafe_b64encode(myurl.encode()).decode().strip("=")
            finalurl = ''.join([url, "/", urlid])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = strip_json_escapes(json.loads(response.text))
            add_records('virustotal', 'vturlwork', vttext)
            attrs = vttext.get('data', {}).get('attributes', {})

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nURL NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nURL NOT FOUND!")
            else:
                if (cv.bkg == 1):
                    if ('last_final_url' in attrs):
                        last_final_url = attrs['last_final_url']
                        print(mycolors.foreground.lightred + "\nLast Final URL: ".ljust(26) + mycolors.reset + str(last_final_url), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.lightred + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.lightred + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.lightred + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.lightred + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                    if ('last_http_response_content_sha256' in attrs):
                        last_http_sha256 = attrs['last_http_response_content_sha256']
                        print(mycolors.foreground.yellow + "\n\nLast SHA256 Content: ".ljust(27) + mycolors.reset + last_http_sha256, end='')
                    if ('last_http_response_code' in attrs):
                        last_http_response = attrs['last_http_response_code']
                        print(mycolors.foreground.yellow + "\nLast HTTP Response Code: ".ljust(26) + mycolors.reset + str(last_http_response), end='')
                    if ('last_analysis_date' in attrs):
                        last_analysis_date = attrs['last_analysis_date']
                        print(mycolors.foreground.yellow + "\nLast Analysis Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                    if ('times_submitted' in attrs):
                        times_submitted = attrs['times_submitted']
                        print(mycolors.foreground.yellow + "\nTimes Submitted: ".ljust(26) + mycolors.reset + str(times_submitted), end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.yellow + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                    if ('threat_names' in attrs):
                        print(mycolors.foreground.lightcyan + "\n\nThreat Names: ", end='')
                        for name in attrs['threat_names']:
                            print(mycolors.reset + "\n".ljust(26) + str(name), end='')
                    if ('redirection_chain' in attrs):
                        print(mycolors.foreground.lightcyan + "\n\nRedirection Chain: ", end='')
                        for chain in attrs['redirection_chain']:
                            print(mycolors.reset + "\n".ljust(26) + str(chain), end='')

                    self.vt_url_ip_domain_report_dark(vttext)

                if (cv.bkg == 0):
                    if ('last_final_url' in attrs):
                        last_final_url = attrs['last_final_url']
                        print(mycolors.foreground.red + "\nLast Final URL: ".ljust(26) + mycolors.reset + str(last_final_url), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('harmless' in attrs['last_analysis_stats']):
                            harmless = attrs['last_analysis_stats']['harmless']
                            print(mycolors.foreground.red + "\nHarmless: ".ljust(26) + mycolors.reset + str(harmless), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('malicious' in attrs['last_analysis_stats']):
                            malicious = attrs['last_analysis_stats']['malicious']
                            print(mycolors.foreground.red + "\nMalicious: ".ljust(26) + mycolors.reset + str(malicious), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('undetected' in attrs['last_analysis_stats']):
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.red + "\nUndetected: ".ljust(26) + mycolors.reset + str(undetected), end='')
                    if ('last_analysis_stats' in attrs):
                        if ('suspicious' in attrs['last_analysis_stats']):
                            suspicious = attrs['last_analysis_stats']['suspicious']
                            print(mycolors.foreground.red + "\nSuspicious: ".ljust(26) + mycolors.reset + str(suspicious), end='')
                    if ('last_http_response_content_sha256' in attrs):
                        last_http_sha256 = attrs['last_http_response_content_sha256']
                        print(mycolors.foreground.purple + "\n\nLast SHA256 Content: ".ljust(27) + mycolors.reset + last_http_sha256, end='')
                    if ('last_http_response_code' in attrs):
                        last_http_response = attrs['last_http_response_code']
                        print(mycolors.foreground.purple + "\nLast HTTP Response Code: ".ljust(26) + mycolors.reset + str(last_http_response), end='')
                    if ('last_analysis_date' in attrs):
                        last_analysis_date = attrs['last_analysis_date']
                        print(mycolors.foreground.purple + "\nLast Analysis Date: ".ljust(26) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                    if ('times_submitted' in attrs):
                        times_submitted = attrs['times_submitted']
                        print(mycolors.foreground.purple + "\nTimes Submitted: ".ljust(26) + mycolors.reset + str(times_submitted), end='')
                    if ('reputation' in attrs):
                        reputation = attrs['reputation']
                        print(mycolors.foreground.purple + "\nReputation: ".ljust(26) + mycolors.reset + str(reputation), end='')
                    if ('threat_names' in attrs):
                        print(mycolors.foreground.green + "\n\nThreat Names: ", end='')
                        for name in attrs['threat_names']:
                            print(mycolors.reset + "\n".ljust(26) + str(name), end='')
                    if ('redirection_chain' in attrs):
                        print(mycolors.foreground.green + "\n\nRedirection Chain: ", end='')
                        for chain in attrs['redirection_chain']:
                            print(mycolors.reset + "\n".ljust(26) + str(chain), end='')

                    self.vt_url_ip_domain_report_light(vttext)

                print("\n")
        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtuploadfile(self, file_item, url=None):
        if not file_item or not os.path.isfile(file_item):
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid file.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid file.\n")
            return False

        if not url:
            url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = url
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            with open(file_item, 'rb') as file_handle:
                files = {'file': (os.path.basename(file_item), file_handle)}
                response = requestsession.post(finalurl, files=files)
            vttext = strip_json_escapes(json.loads(response.text))
            add_records('virustotal', 'vtuploadfile', vttext)

            if (response.status_code == 400):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\tThere was an issue while uploading the file.")
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "\tThere was an issue while uploading the file.")
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "\n\tFile Submitted!" + mycolors.reset)
                    print(mycolors.foreground.lightcyan + "\n\tid: " + mycolors.reset + vttext['data']['id'])
                    print(mycolors.foreground.yellow + "\n\tWait for 120 seconds (at least) before requesting the report using -v 1 or -v 8 options!" + mycolors.reset)
                if (cv.bkg == 0):
                    print(mycolors.foreground.green + "\n\tFile Submitted!" + mycolors.reset)
                    print(mycolors.foreground.green + "\n\tid: " + mycolors.reset + vttext['data']['id'])
                    print(mycolors.foreground.purple + "\n\tWait for 120 seconds (at least) before requesting the report using -v 1 or -v 8 options!" + mycolors.reset)
        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtreportwork(self, myhash, prolog):
        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/", quote(myhash, safe='')])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = strip_json_escapes(json.loads(response.text))
            add_records('virustotal', 'vtreportwork', vttext)
            attrs = vttext.get('data', {}).get('attributes', {})

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nSAMPLE NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nSAMPLE NOT FOUND!")
            else:
                if (cv.bkg == 1):
                    if (prolog == 1):
                        if ('md5' in attrs):
                            md5hash = attrs['md5']
                            print(mycolors.foreground.lightcyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                        if ('sha1' in attrs):
                            sha1hash = attrs['sha1']
                            print(mycolors.foreground.lightcyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                        if ('sha256' in attrs):
                            sha256hash = attrs['sha256']
                            print(mycolors.foreground.lightcyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                        if ('last_analysis_stats' in attrs):
                            malicious = attrs['last_analysis_stats']['malicious']
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.lightred + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                            print(mycolors.foreground.lightred + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')

                    print(mycolors.foreground.lightred + "\nAV Report:", end='')
                    if ('last_analysis_results' in attrs):
                        ok = "CLEAN"
                        if ('Avast' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Avast']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Avira' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Avira']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('BitDefender' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['BitDefender']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('DrWeb' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['DrWeb']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Emsisoft' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Emsisoft']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('ESET-NOD32' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['ESET-NOD32']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('F-Secure' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['F-Secure']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('FireEye' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['FireEye']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Fortinet' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Fortinet']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Kaspersky' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Kaspersky']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('McAfee' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['McAfee']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Microsoft' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Microsoft']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Panda' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Panda']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Sophos' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Sophos']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Symantec' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Symantec']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('TrendMicro' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['TrendMicro']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('ZoneAlarm' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['ZoneAlarm']['result']
                            if (result):
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.lightcyan + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + ok, end='')

                if (cv.bkg == 0):
                    if (prolog == 1):
                        if ('md5' in attrs):
                            md5hash = attrs['md5']
                            print(mycolors.foreground.blue + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                        if ('sha1' in attrs):
                            sha1hash = attrs['sha1']
                            print(mycolors.foreground.blue + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                        if ('sha256' in attrs):
                            sha256hash = attrs['sha256']
                            print(mycolors.foreground.blue + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                        if ('last_analysis_stats' in attrs):
                            malicious = attrs['last_analysis_stats']['malicious']
                            undetected = attrs['last_analysis_stats']['undetected']
                            print(mycolors.foreground.red + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                            print(mycolors.foreground.red + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')

                    print(mycolors.foreground.red + "\nAV Report:", end='')
                    ok = "CLEAN"
                    if ('last_analysis_results' in attrs):
                        if ('Avast' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Avast']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Avast: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Avira' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Avira']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Avira: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('BitDefender' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['BitDefender']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "BitDefender: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('DrWeb' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['DrWeb']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "DrWeb: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Emsisoft' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Emsisoft']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Emsisoft: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('ESET-NOD32' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['ESET-NOD32']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "ESET-NOD32: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('F-Secure' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['F-Secure']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "F-Secure: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('FireEye' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['FireEye']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "FireEye: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Fortinet' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Fortinet']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Fortinet: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Kaspersky' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Kaspersky']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Kaspersky: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('McAfee' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['McAfee']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "McAfee: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Microsoft' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Microsoft']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Microsoft: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Panda' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Panda']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Panda: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Sophos' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Sophos']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Sophos: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('Symantec' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['Symantec']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Symantec: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('TrendMicro' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['TrendMicro']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "TrendMicro: ".ljust(15) + mycolors.reset + ok, end='')
                    if ('last_analysis_results' in attrs):
                        if ('ZoneAlarm' in attrs['last_analysis_results']):
                            result = attrs['last_analysis_results']['ZoneAlarm']['result']
                            if (result):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + result, end='')
                            else:
                                print(mycolors.foreground.blue + "\n".ljust(22) + "ZoneAlarm: ".ljust(15) + mycolors.reset + ok, end='')

                print("\n")

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def _vtsignature(self, attrs):
        signature = attrs.get('signature_info')
        if not isinstance(signature, dict) or not signature:
            return

        if (cv.bkg == 1):
            headcolor = mycolors.foreground.lightred
            labelcolor = mycolors.foreground.yellow
        else:
            headcolor = mycolors.foreground.red
            labelcolor = mycolors.foreground.blue

        print(headcolor + "\n\nSignature: ", end='')

        for key, label in (('verified', 'Verified: '), ('signing date', 'Signed On: ')):
            if signature.get(key):
                print(labelcolor + "\n".ljust(22) + label.ljust(15) + mycolors.reset + str(signature[key]), end='')

        for key, label in (('signers', 'Signers: '), ('counter signers', 'Counter Sig: ')):
            if signature.get(key):
                print(labelcolor + "\n".ljust(22) + label.ljust(15), end='')
                for name in str(signature[key]).split(';'):
                    if name.strip():
                        print(mycolors.reset + "\n".ljust(37) + name.strip(), end='')

        details = signature.get('signers details')
        if not isinstance(details, list):
            details = signature.get('x509')
        if isinstance(details, list) and details:
            print(labelcolor + "\n".ljust(22) + "Certificates: ", end='')
            for certificate in details:
                if not isinstance(certificate, dict):
                    continue
                first = True
                for key in ('name', 'status', 'algorithm', 'valid from', 'valid to',
                            'serial number', 'cert issuer', 'thumbprint'):
                    if certificate.get(key):
                        margin = "\n\n".ljust(38) if first else "\n".ljust(37)
                        value = wrap_field(certificate[key], SIG_REPORT_WIDTH,
                                           SIG_FIELD_INDENT + SIG_LABEL_WIDTH)
                        print(mycolors.reset + margin + (key + ': ').ljust(SIG_LABEL_WIDTH) + value, end='')
                        first = False

        if str(signature.get('verified', '')).strip().lower() == 'signed':
            print(labelcolor + "\n\n".ljust(23)
                  + wrap_field("Signed is VirusTotal's check that the file still matches its certificate, "
                               "not a verdict on the file. Revocation is not reflected here.",
                               SIG_REPORT_WIDTH, SIG_SECTION_INDENT),
                  end='')

    def vthashwork(self, myhash, showreport):
        if len(myhash) not in [32, 40, 64]:
            if cv.bkg == 0:
                print(mycolors.foreground.red + "\nYou didn't provide a valid hash.\n")
            else:
                print(mycolors.foreground.yellow + "\nYou didn't provide a valid hash.\n")
            return False

        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/", quote(myhash, safe='')])
            requestsession = create_session()
            requestsession.headers.update({"x-apikey": self.VTAPI})
            requestsession.headers.update({"accept": "application/json"})
            response = requestsession.get(finalurl)
            vttext = strip_json_escapes(json.loads(response.text))
            attrs = vttext.get('data', {}).get('attributes', {})

            if (response.status_code != 404):
                stats = attrs.get('last_analysis_stats', {}) or {}
                classification = attrs.get('popular_threat_classification', {}) or {}
                signature = attrs.get('signature_info', {}) or {}
                signerdetails = signature.get('signers details')
                if not isinstance(signerdetails, list) or not signerdetails:
                    signerdetails = [{}]
                signercert = signerdetails[0] if isinstance(signerdetails[0], dict) else {}
                collector.add({
                    'service': 'virustotal',
                    'query': myhash,
                    'md5': attrs.get('md5'),
                    'sha1': attrs.get('sha1'),
                    'sha256': attrs.get('sha256'),
                    'malicious': stats.get('malicious'),
                    'undetected': stats.get('undetected'),
                    'harmless': stats.get('harmless'),
                    'suspicious': stats.get('suspicious'),
                    'type_description': attrs.get('type_description'),
                    'size': attrs.get('size'),
                    'threat_label': classification.get('suggested_threat_label'),
                    'magic': attrs.get('magic'),
                    'reputation': attrs.get('reputation'),
                    'signature_verified': signature.get('verified'),
                    'signature_signers': signature.get('signers'),
                    'signature_date': signature.get('signing date'),
                    'signature_algorithm': signercert.get('algorithm'),
                    'signature_thumbprint': signercert.get('thumbprint'),
                    'signature_serial': signercert.get('serial number'),
                })

            if not is_text_output():
                return True

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\nSAMPLE NOT FOUND!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.red + "\nSAMPLE NOT FOUND!")
            else:
                if (cv.bkg == 1):
                    if ('md5' in attrs):
                        md5hash = attrs['md5']
                        print(mycolors.foreground.lightcyan + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                    if ('sha1' in attrs):
                        sha1hash = attrs['sha1']
                        print(mycolors.foreground.lightcyan + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                    if ('sha256' in attrs):
                        sha256hash = attrs['sha256']
                        print(mycolors.foreground.lightcyan + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                    if ('last_analysis_stats' in attrs):
                        malicious = attrs['last_analysis_stats']['malicious']
                        undetected = attrs['last_analysis_stats']['undetected']
                        print(mycolors.foreground.lightred + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                        print(mycolors.foreground.lightred + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')
                    if ('type_description' in attrs):
                        type_description = attrs['type_description']
                        print(mycolors.foreground.yellow + "\nType Description: ".ljust(22) + mycolors.reset + type_description, end='')
                    if ('size' in attrs):
                        size = attrs['size']
                        print(mycolors.foreground.yellow + "\nSize: ".ljust(22) + mycolors.reset + str(size), end='')
                    if ('last_analysis_date' in attrs):
                        last_analysis_date = attrs['last_analysis_date']
                        print(mycolors.foreground.yellow + "\nLast Analysis Date: ".ljust(22) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                    if ('type_tag' in attrs):
                        type_tag = attrs['type_tag']
                        print(mycolors.foreground.yellow + "\nType Tag: ".ljust(22) + mycolors.reset + type_tag, end='')
                    if ('times_submitted' in attrs):
                        times_submitted = attrs['times_submitted']
                        print(mycolors.foreground.yellow + "\nTimes Submitted: ".ljust(22) + mycolors.reset + str(times_submitted), end='')
                    if ('popular_threat_classification' in attrs):
                        print(mycolors.foreground.lightred + "\n\nThreat Label: ".ljust(23), end='')
                        if ('suggested_threat_label' in attrs['popular_threat_classification']):
                            threat_label = attrs['popular_threat_classification']['suggested_threat_label']
                        else:
                            threat_label = 'NO GIVEN NAME'
                        print(mycolors.reset + str(threat_label), end='')
                        if ('popular_threat_category' in attrs['popular_threat_classification']):
                            print(mycolors.foreground.lightred + "\nClassification: ", end='')
                            for popular in attrs['popular_threat_classification']['popular_threat_category']:
                                count = popular['count']
                                value = popular['value']
                                print(mycolors.reset + "\n".ljust(22) + "popular count: ".ljust(15) + str(count), end='')
                                print(mycolors.reset + "\n".ljust(22) + "label: ".ljust(15) + str(value), end='\n')
                    if ('trid' in attrs):
                        print(mycolors.foreground.lightcyan + "\nTrid: ", end='')
                        for trid in attrs['trid']:
                            file_type = trid['file_type']
                            probability = trid['probability']
                            print(mycolors.reset + "\n".ljust(22) + "file_type: ".ljust(15) + str(file_type), end='')
                            print(mycolors.reset + "\n".ljust(22) + "probability: ".ljust(15) + str(probability), end='\n')
                    if ('names' in attrs):
                        print(mycolors.foreground.lightcyan + "\nNames: ", end='')
                        for name in attrs['names']:
                            print(mycolors.reset + ("\n".ljust(22) + (mycolors.reset + "\n".ljust(22)).join(textwrap.wrap(" ".join(name.split()), width=80))), end=' ')
                    if ('pe_info' in attrs):
                        print(mycolors.foreground.lightred + "\n\nPE Info: ", end='')
                        if ('imphash' in attrs['pe_info']):
                            imphash = attrs['pe_info']['imphash']
                            print(mycolors.foreground.yellow + "\n".ljust(22) + "Imphash: ".ljust(15) + mycolors.reset + str(imphash), end='')
                        if ('overlay' in attrs['pe_info']):
                            print(mycolors.foreground.yellow + "\n".ljust(22) + "Overlay: ".ljust(15) + mycolors.reset + "YES", end='')
                            if ('size' in attrs['pe_info']['overlay']):
                                print(mycolors.foreground.yellow + "\n".ljust(22) + "Overlay Size: ".ljust(15) + mycolors.reset + humansize(attrs['pe_info']['overlay']['size']), end='')
                        else:
                            print(mycolors.foreground.yellow + "\n".ljust(22) + "Overlay: ".ljust(15) + mycolors.reset + "NO", end='')
                        if ('import_list' in attrs['pe_info']):
                            print(mycolors.foreground.yellow + "\n".ljust(22) + "Libraries: ".ljust(15), end='')
                            for lib in attrs['pe_info']['import_list']:
                                print(mycolors.reset + "\n".ljust(37) + str(lib['library_name']), end='')
                        if ('sections' in attrs['pe_info']):
                            print(mycolors.foreground.yellow + "\n".ljust(22) + "Sections: ", end='')
                            for section in attrs['pe_info']['sections']:
                                if ('name' in section):
                                    section_name = section['name']
                                    print(mycolors.reset + "\n\n".ljust(38) + "section_name: ".ljust(14) + str(section_name), end=' ')
                                if ('virtual_size' in section):
                                    virtual_size = section['virtual_size']
                                    print(mycolors.reset + "\n".ljust(37) + "virtual_size: ".ljust(14) + str(virtual_size), end=' ')
                                if ('entropy' in section):
                                    entropy = section['entropy']
                                    print(mycolors.reset + "\n".ljust(37) + "entropy: ".ljust(14) + str(entropy), end=' ')
                                if ('flags' in section):
                                    flags = section['flags']
                                    print(mycolors.reset + "\n".ljust(37) + "flags: ".ljust(14) + str(flags), end=' ')
                    if ('androguard' in attrs):
                        print(mycolors.foreground.lightcyan + "\n\nAndroguard: ", end='')
                        if ('Activities' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Activities: ".ljust(23), end='')
                            for activity in attrs['androguard']['Activities']:
                                print(mycolors.reset + "\n".ljust(37) + activity, end='')
                        if ('main_activity' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n\n".ljust(23) + "MainActivity: ".ljust(15), end='')
                            mainactivity = attrs['androguard']['main_activity']
                            print(mycolors.reset + mainactivity, end='')
                        if ('Package' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Package: ".ljust(15), end='')
                            mainactivity = attrs['androguard']['Package']
                            print(mycolors.reset + mainactivity, end='\n')
                        if ('Providers' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Providers: ".ljust(23), end='')
                            for provider in attrs['androguard']['Providers']:
                                print(mycolors.reset + "\n".ljust(37) + provider, end='')
                        if ('Receivers' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Receivers: ".ljust(23), end='')
                            for receiver in attrs['androguard']['Receivers']:
                                print(mycolors.reset + "\n".ljust(37) + receiver, end='')
                        if ('Libraries' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Libraries: ".ljust(23), end='')
                            for library in attrs['androguard']['Libraries']:
                                print(mycolors.reset + "\n".ljust(37) + library, end='')
                        if ('Services' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Services: ".ljust(23), end='')
                            for service in attrs['androguard']['Services']:
                                print(mycolors.reset + "\n".ljust(37) + service, end='')
                        if ('StringsInformation' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "StringsInfo: ".ljust(23), end='')
                            for string in attrs['androguard']['StringsInformation']:
                                print(mycolors.reset + "\n".ljust(37) + string, end='')
                        if ('certificate' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Certificate: ", end='')
                            if ('Issuer' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Issuer: ".ljust(15), end=' ')
                                if ('DN' in attrs['androguard']['certificate']['Issuer']):
                                    dn = attrs['androguard']['certificate']['Issuer']['DN']
                                    print(mycolors.reset + "DN: " + dn, end='')
                            if ('Subject' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Subject: ".ljust(15), end=' ')
                                if ('DN' in attrs['androguard']['certificate']['Subject']):
                                    dn = attrs['androguard']['certificate']['Subject']['DN']
                                    print(mycolors.reset + "DN: " + dn, end='')
                            if ('serialnumber' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "SerialNumber: ".ljust(15), end=' ')
                                serialnumber = attrs['androguard']['certificate']['serialnumber']
                                print(mycolors.reset + serialnumber, end='')
                            if ('validfrom' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "ValidFrom: ".ljust(15), end=' ')
                                validfrom = attrs['androguard']['certificate']['validfrom']
                                print(mycolors.reset + validfrom, end='')
                            if ('validto' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "ValidTo: ".ljust(15), end=' ')
                                validto = attrs['androguard']['certificate']['validto']
                                print(mycolors.reset + validto, end='')
                            if ('thumbprint' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Thumbprint: ".ljust(15), end=' ')
                                thumbprint = attrs['androguard']['certificate']['thumbprint']
                                print(mycolors.reset + thumbprint, end='')
                        if ('intent_filters' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "IntentFilters: ", end='')
                            if ('Activities' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Activities: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Activities']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                            if ('Receivers' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Receivers: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Receivers']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                            if ('Services' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.lightcyan + "\n".ljust(37) + "Services: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Services']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "category: ".ljust(11) + mycolors.reset + category, end='')
                        if ('permission_details' in attrs['androguard']):
                            print(mycolors.foreground.lightred + "\n".ljust(22) + "Permissions: ", end='')
                            for key, value in (attrs['androguard']['permission_details']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.yellow + "name: ".ljust(11) + mycolors.reset + key, end='')
                                if ('full_description' in value):
                                    print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.lightcyan + "details: ".ljust(11) + mycolors.reset + (mycolors.reset + "\n".ljust(64)).join(textwrap.wrap(" ".join(value['full_description'].split()), width=80))), end=' ')
                                if ('permission_type' in value):
                                    print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.lightcyan + "type: ".ljust(11) + mycolors.reset + value['permission_type'], end='')
                                if ('short_description' in value):
                                    print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.lightcyan + "info: ".ljust(11) + mycolors.reset + ("\n" + mycolors.reset + "".ljust(63)).join(textwrap.wrap(value['short_description'], width=80))), end=' ')

                    self._vtsignature(attrs)

                    print("\n")

                    if (showreport == 1):
                        self.vtreportwork(myhash, 0)

                if (cv.bkg == 0):
                    if ('md5' in attrs):
                        md5hash = attrs['md5']
                        print(mycolors.foreground.blue + "\nMD5 hash: ".ljust(22) + mycolors.reset + md5hash, end='')
                    if ('sha1' in attrs):
                        sha1hash = attrs['sha1']
                        print(mycolors.foreground.blue + "\nSHA1 hash: ".ljust(22) + mycolors.reset + sha1hash, end='')
                    if ('sha256' in attrs):
                        sha256hash = attrs['sha256']
                        print(mycolors.foreground.blue + "\nSHA256 hash: ".ljust(22) + mycolors.reset + sha256hash, end='')
                    if ('last_analysis_stats' in attrs):
                        malicious = attrs['last_analysis_stats']['malicious']
                        undetected = attrs['last_analysis_stats']['undetected']
                        print(mycolors.foreground.red + "\n\nMalicious: ".ljust(23) + mycolors.reset + str(malicious), end='')
                        print(mycolors.foreground.red + "\nUndetected: ".ljust(22) + mycolors.reset + str(undetected), end='\n')
                    if ('type_description' in attrs):
                        type_description = attrs['type_description']
                        print(mycolors.foreground.purple + "\nType Description: ".ljust(22) + mycolors.reset + type_description, end='')
                    if ('size' in attrs):
                        size = attrs['size']
                        print(mycolors.foreground.purple + "\nSize: ".ljust(22) + mycolors.reset + str(size), end='')
                    if ('last_analysis_date' in attrs):
                        last_analysis_date = attrs['last_analysis_date']
                        print(mycolors.foreground.purple + "\nLast Analysis Date: ".ljust(22) + mycolors.reset + str(datetime.fromtimestamp(last_analysis_date)), end='')
                    if ('type_tag' in attrs):
                        type_tag = attrs['type_tag']
                        print(mycolors.foreground.blue + "\nType Tag: ".ljust(22) + mycolors.reset + type_tag, end='')
                    if ('times_submitted' in attrs):
                        times_submitted = attrs['times_submitted']
                        print(mycolors.foreground.blue + "\nTimes Submitted: ".ljust(22) + mycolors.reset + str(times_submitted), end='')
                    if ('popular_threat_classification' in attrs):
                        print(mycolors.foreground.red + "\n\nThreat Label: ".ljust(23), end='')
                        if ('suggested_threat_label' in attrs['popular_threat_classification']):
                            threat_label = attrs['popular_threat_classification']['suggested_threat_label']
                        else:
                            threat_label = 'NO GIVEN NAME'
                        print(mycolors.reset + str(threat_label), end='')
                        if ('popular_threat_category' in attrs['popular_threat_classification']):
                            print(mycolors.foreground.red + "\nClassification: ", end='')
                            for popular in attrs['popular_threat_classification']['popular_threat_category']:
                                count = popular['count']
                                value = popular['value']
                                print(mycolors.reset + "\n".ljust(22) + "popular count: ".ljust(15) + str(count), end='')
                                print(mycolors.reset + "\n".ljust(22) + "label: ".ljust(15) + str(value), end='\n')
                    if ('trid' in attrs):
                        print(mycolors.foreground.blue + "\nTrid: ", end='')
                        for trid in attrs['trid']:
                            file_type = trid['file_type']
                            probability = trid['probability']
                            print(mycolors.reset + "\n".ljust(22) + "file_type: ".ljust(15) + str(file_type), end='')
                            print(mycolors.reset + "\n".ljust(22) + "probability: ".ljust(15) + str(probability), end='\n')
                    if ('names' in attrs):
                        print(mycolors.foreground.blue + "\nNames: ", end='')
                        for name in attrs['names']:
                            print(mycolors.reset + ("\n".ljust(22) + (mycolors.reset + "\n".ljust(22)).join(textwrap.wrap(" ".join(name.split()), width=80))), end=' ')
                    if ('pe_info' in attrs):
                        print(mycolors.foreground.red + "\n\nPE Info: ", end='')
                        if ('imphash' in attrs['pe_info']):
                            imphash = attrs['pe_info']['imphash']
                            print(mycolors.foreground.blue + "\n".ljust(22) + "Imphash: ".ljust(15) + mycolors.reset + str(imphash), end='')
                        if ('overlay' in attrs['pe_info']):
                            print(mycolors.foreground.blue + "\n".ljust(22) + "Overlay: ".ljust(15) + mycolors.reset + "YES", end='')
                            if ('size' in attrs['pe_info']['overlay']):
                                print(mycolors.foreground.blue + "\n".ljust(22) + "Overlay Size: ".ljust(15) + mycolors.reset + humansize(attrs['pe_info']['overlay']['size']), end='')
                        else:
                            print(mycolors.foreground.blue + "\n".ljust(22) + "Overlay: ".ljust(15) + mycolors.reset + "NO", end='')
                        if ('import_list' in attrs['pe_info']):
                            print(mycolors.foreground.blue + "\n".ljust(22) + "Libraries: ".ljust(15), end='')
                            for lib in attrs['pe_info']['import_list']:
                                print(mycolors.reset + "\n".ljust(37) + str(lib['library_name']), end='')
                        if ('sections' in attrs['pe_info']):
                            print(mycolors.foreground.blue + "\n".ljust(22) + "Sections: ", end='')
                            for section in attrs['pe_info']['sections']:
                                if ('name' in section):
                                    section_name = section['name']
                                    print(mycolors.reset + "\n\n".ljust(38) + "section_name: ".ljust(14) + str(section_name), end=' ')
                                if ('virtual_size' in section):
                                    virtual_size = section['virtual_size']
                                    print(mycolors.reset + "\n".ljust(37) + "virtual_size: ".ljust(14) + str(virtual_size), end=' ')
                                if ('entropy' in section):
                                    entropy = section['entropy']
                                    print(mycolors.reset + "\n".ljust(37) + "entropy: ".ljust(14) + str(entropy), end=' ')
                                if ('flags' in section):
                                    flags = section['flags']
                                    print(mycolors.reset + "\n".ljust(37) + "flags: ".ljust(14) + str(flags), end=' ')
                    if ('androguard' in attrs):
                        print(mycolors.foreground.blue + "\n\nAndroguard: ", end='')
                        if ('Activities' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Activities: ".ljust(23), end='')
                            for activity in attrs['androguard']['Activities']:
                                print(mycolors.reset + "\n".ljust(37) + activity, end='')
                        if ('main_activity' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n\n".ljust(23) + "MainActivity: ".ljust(15), end='')
                            mainactivity = attrs['androguard']['main_activity']
                            print(mycolors.reset + mainactivity, end='')
                        if ('Package' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Package: ".ljust(15), end='')
                            mainactivity = attrs['androguard']['Package']
                            print(mycolors.reset + mainactivity, end='\n')
                        if ('Providers' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Providers: ".ljust(23), end='')
                            for provider in attrs['androguard']['Providers']:
                                print(mycolors.reset + "\n".ljust(37) + provider, end='')
                        if ('Receivers' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Receivers: ".ljust(23), end='')
                            for receiver in attrs['androguard']['Receivers']:
                                print(mycolors.reset + "\n".ljust(37) + receiver, end='')
                        if ('Libraries' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Libraries: ".ljust(23), end='')
                            for library in attrs['androguard']['Libraries']:
                                print(mycolors.reset + "\n".ljust(37) + library, end='')
                        if ('Services' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Services: ".ljust(23), end='')
                            for service in attrs['androguard']['Services']:
                                print(mycolors.reset + "\n".ljust(37) + service, end='')
                        if ('StringsInformation' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "StringsInfo: ".ljust(23), end='')
                            for string in attrs['androguard']['StringsInformation']:
                                print(mycolors.reset + "\n".ljust(37) + string, end='')
                        if ('certificate' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Certificate: ", end='')
                            if ('Issuer' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Issuer: ".ljust(15), end=' ')
                                if ('DN' in attrs['androguard']['certificate']['Issuer']):
                                    dn = attrs['androguard']['certificate']['Issuer']['DN']
                                    print(mycolors.reset + "DN: " + dn, end='')
                            if ('Subject' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Subject: ".ljust(15), end=' ')
                                if ('DN' in attrs['androguard']['certificate']['Subject']):
                                    dn = attrs['androguard']['certificate']['Subject']['DN']
                                    print(mycolors.reset + "DN: " + dn, end='')
                            if ('serialnumber' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "SerialNumber: ".ljust(15), end=' ')
                                serialnumber = attrs['androguard']['certificate']['serialnumber']
                                print(mycolors.reset + serialnumber, end='')
                            if ('validfrom' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "ValidFrom: ".ljust(15), end=' ')
                                validfrom = attrs['androguard']['certificate']['validfrom']
                                print(mycolors.reset + validfrom, end='')
                            if ('validto' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "ValidTo: ".ljust(15), end=' ')
                                validto = attrs['androguard']['certificate']['validto']
                                print(mycolors.reset + validto, end='')
                            if ('thumbprint' in attrs['androguard']['certificate']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Thumbprint: ".ljust(15), end=' ')
                                thumbprint = attrs['androguard']['certificate']['thumbprint']
                                print(mycolors.reset + thumbprint, end='')
                        if ('intent_filters' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "IntentFilters: ", end='')
                            if ('Activities' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Activities: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Activities']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.blue + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.blue + "category: ".ljust(11) + mycolors.reset + category, end='')
                            if ('Receivers' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Receivers: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Receivers']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.blue + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.blue + "category: ".ljust(11) + mycolors.reset + category, end='')
                            if ('Services' in attrs['androguard']['intent_filters']):
                                print(mycolors.foreground.blue + "\n".ljust(37) + "Services: ".ljust(15), end=' ')
                                for key, value in (attrs['androguard']['intent_filters']['Services']).items():
                                    print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key, end='')
                                    if ('action' in value):
                                        for action_item in value['action']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.blue + "action: ".ljust(11) + mycolors.reset + action_item, end='')
                                    if ('category' in value):
                                        for category in value['category']:
                                            print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.blue + "category: ".ljust(11) + mycolors.reset + category, end='')
                        if ('permission_details' in attrs['androguard']):
                            print(mycolors.foreground.red + "\n".ljust(22) + "Permissions: ", end='')
                            for key, value in (attrs['androguard']['permission_details']).items():
                                print(mycolors.reset + "\n\n".ljust(54) + mycolors.foreground.purple + "name: ".ljust(11) + mycolors.reset + key, end='')
                                if ('full_description' in value):
                                    print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.blue + "details: ".ljust(11) + mycolors.reset + (mycolors.reset + "\n".ljust(64)).join(textwrap.wrap(" ".join(value['full_description'].split()), width=80))), end=' ')
                                if ('permission_type' in value):
                                    print(mycolors.reset + "\n".ljust(53) + mycolors.foreground.blue + "type: ".ljust(11) + mycolors.reset + value['permission_type'], end='')
                                if ('short_description' in value):
                                    print(mycolors.reset + ("\n".ljust(53) + mycolors.foreground.blue + "info: ".ljust(11) + mycolors.reset + ("\n" + mycolors.reset + "".ljust(63)).join(textwrap.wrap(value['short_description'], width=80))), end=' ')

                    self._vtsignature(attrs)

                    print("\n")

                    if (showreport == 1):
                        self.vtreportwork(myhash, 0)
        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtlargefile(self, file_item):
        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/upload_url"])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = strip_json_escapes(json.loads(response.text))
            add_records('virustotal', 'vtlargefile', vttext)

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\tThere was an issue while getting a URL for uploading the file.")
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "\tThere was an issue while getting a URL for uploading the file.")
            else:
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\n\tUploading file...")
                    self.vtuploadfile(file_item, url=vttext['data'])
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "\n\tUploading file...")
                    self.vtuploadfile(file_item, url=vttext['data'])

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtbatchwork(self, myhash):
        url = VirusTotalExtractor.urlfilevt3

        type_description = 'NOT FOUND'
        threat_label = 'NOT FOUND'
        malicious = 'NOT FOUND'

        try:

            finalurl = ''.join([url, "/", quote(myhash.strip(), safe='')])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = strip_json_escapes(json.loads(response.text))
            add_records('virustotal', 'vtbatchwork', vttext)
            attrs = vttext.get('data', {}).get('attributes', {})

            if (response.status_code == 404):
                return (type_description, threat_label, malicious)
            else:
                if ('type_description' in attrs):
                    type_description = attrs['type_description']
                else:
                    type_description = 'NO DESCRIPTION'
                if ('popular_threat_classification' in attrs):
                    if ('suggested_threat_label' in attrs['popular_threat_classification']):
                        threat_label = attrs['popular_threat_classification']['suggested_threat_label']
                else:
                    threat_label = 'NO GIVEN NAME'
                if ('last_analysis_stats' in attrs):
                    if ('malicious' in attrs['last_analysis_stats']):
                        malicious = attrs['last_analysis_stats']['malicious']
                else:
                    malicious = 'NOT FOUND'

                return (type_description, threat_label, malicious)

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtbatchcheck(self, filename, apitype):
        type_description = ''
        threat_label = ''
        malicious = ''
        apitype_var = apitype

        try:
            header = ("Sample".center(9) + "Hash".center(68) + "Description".center(30)
                      + "Threat Label".center(26) + "AV Detection".center(24))
            print("\n" + mycolors.foreground.neutral(cv.bkg) + header + mycolors.reset)
            print(divider(display_width(header)), end="\n\n")

            with open(filename, 'r') as fh:
                filelines = fh.readlines()

            hashnumber = 0
            for hashitem in filelines:
                hashnumber = hashnumber + 1
                (type_description, threat_label, malicious) = self.vtbatchwork(hashitem)
                if (type_description == "NOT FOUND"):
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "hash_" + str(hashnumber) + "\t   " + mycolors.reset + (hashitem.strip()).ljust(79) + mycolors.foreground.yellow + (type_description).ljust(28) + mycolors.foreground.lightcyan + (threat_label).ljust(26) + mycolors.foreground.lightred + str(malicious))
                    if (cv.bkg == 0):
                        print(mycolors.foreground.purple + "hash_" + str(hashnumber) + "\t   " + mycolors.reset + (hashitem.strip()).ljust(79) + mycolors.foreground.blue + (type_description).ljust(28) + mycolors.foreground.blue + (threat_label).ljust(26) + mycolors.foreground.red + str(malicious))
                    if (apitype_var == 1):
                        if ((hashnumber % 4) == 0):
                            time.sleep(61)
                else:
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightcyan + "hash_" + str(hashnumber) + "\t   " + mycolors.reset + (hashitem.strip()).ljust(68) + mycolors.foreground.yellow + (type_description).ljust(30) + mycolors.foreground.lightcyan + (threat_label).ljust(34) + mycolors.foreground.lightred + str(malicious))
                    if (cv.bkg == 0):
                        print(mycolors.foreground.purple + "hash_" + str(hashnumber) + "\t   " + mycolors.reset + (hashitem.strip()).ljust(68) + mycolors.foreground.blue + (type_description).ljust(30) + mycolors.foreground.blue + (threat_label).ljust(34) + mycolors.foreground.red + str(malicious))
                    if (apitype_var == 1):
                        if ((hashnumber % 4) == 0):
                            time.sleep(61)
        except OSError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "The provided file doesn't exist!\n"))
            else:
                print((mycolors.foreground.red + "The provided file doesn't exist!\n"))
            print(mycolors.reset)
            exit(3)

    def vtbehavior(self, myhash):
        url = VirusTotalExtractor.urlfilevt3

        try:
            finalurl = ''.join([url, "/", quote(myhash, safe=''), "/behaviour_summary"])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)
            vttext = strip_json_escapes(json.loads(response.text))
            add_records('virustotal', 'vtbehavior', vttext)

            if (response.status_code == 404):
                if (cv.bkg == 1):
                    print(mycolors.foreground.yellow + "\tReport not found for the provided hash!")
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + "\tReport not found for the provided hash!")
            else:
                if (cv.bkg == 1):
                    finalhash = myhash
                    print(mycolors.foreground.lightred + "\nProvided Hash: ".ljust(24) + mycolors.reset + finalhash)
                    if ('verdicts' in vttext['data']):
                        print(mycolors.foreground.yellow + "Verdicts: ".ljust(22) + mycolors.reset, end=' ')
                        for verdict in vttext['data']['verdicts']:
                            print(mycolors.reset + (verdict), end=' | ')
                    if ('verdict_confidence' in vttext['data']):
                        print(mycolors.foreground.yellow + "\nVerdict Confidence: ".ljust(24) + mycolors.reset + str(vttext['data']['verdict_confidence']) + mycolors.reset, end=' ')
                    if ('verdict_labels' in vttext['data']):
                        print(mycolors.foreground.yellow + "\nVerdict Labels: ".ljust(23) + mycolors.reset, end=' ')
                        for label in vttext['data']['verdict_labels']:
                            print(mycolors.reset + (label), end=' ')
                    if ('processes_injected' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nProcesses Injected: ", end='')
                        for injected in vttext['data']['processes_injected']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(injected, width=120))), end=' ')
                    if ('calls_highlighted' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nCalls Highlighted: ", end='')
                        for calls in vttext['data']['calls_highlighted']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(calls, width=120))), end=' ')
                    if ('processes_tree' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nProcesses Tree: ", end='')
                        for process in vttext['data']['processes_tree']:
                            print("\n")
                            print(mycolors.reset + " ".ljust(23) + "process_id: ".ljust(15) + process['process_id'], end='')
                            print(mycolors.reset + ("\n".ljust(24) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(39)).join(textwrap.wrap(" ".join(process['name'].split()), width=80))), end=' ')
                            if ('children' in process):
                                print(mycolors.reset + "\n".ljust(24) + "children: ".ljust(15), end='')
                                for child in process['children']:
                                    print(mycolors.reset + "\n".ljust(28) + "process_id: ".ljust(15) + child['process_id'], end='')
                                    print(mycolors.reset + ("\n".ljust(28) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(43)).join(textwrap.wrap(" ".join(child['name'].split()), width=80))), end=' ')
                    if ('processes_terminated' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nProcesses Terminated: ", end='\n')
                        for process_term in vttext['data']['processes_terminated']:
                            print(mycolors.reset + "".ljust(23) + process_term, end='\n')
                    if ('processes_killed' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nProcesses Killed: ", end='\n')
                        for process_kill in vttext['data']['processes_killed']:
                            print(mycolors.reset + "".ljust(23) + process_kill, end='\n')
                    if ('services_created' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nServices Created: ", end='\n')
                        for services_created in vttext['data']['services_created']:
                            print(mycolors.reset + "".ljust(23) + services_created, end='\n')
                    if ('services_deleted' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nServices Deleted: ", end='\n')
                        for services_deleted in vttext['data']['services_deleted']:
                            print(mycolors.reset + "".ljust(23) + services_deleted, end='\n')
                    if ('services_started' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nServices Started: ", end='\n')
                        for services_started in vttext['data']['services_started']:
                            print(mycolors.reset + "".ljust(23) + services_started, end='\n')
                    if ('services_stopped' in vttext['data']):
                        print(mycolors.foreground.lightred + "\n\nServices Stopped: ", end='\n')
                        for services_stopped in vttext['data']['services_stopped']:
                            print(mycolors.reset + "".ljust(23) + services_stopped, end='\n')
                    if ('dns_lookups' in vttext['data']):
                        print(mycolors.foreground.yellow + "\nDNS Lookups: ", end='')
                        for lookup in vttext['data']['dns_lookups']:
                            if ('resolved_ips' in lookup):
                                print(mycolors.reset + "\n".ljust(24) + "resolved_ips: ", end='')
                                for ip in (lookup['resolved_ips']):
                                    print(ip, end=' | ')
                            if ('hostname' in lookup):
                                print(mycolors.reset + "\n".ljust(24) + "hostname: ".ljust(14) + lookup['hostname'], end='\n')
                    if ('ja3_digests' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nJA3 Digests: ", end='\n')
                        for ja3 in vttext['data']['ja3_digests']:
                            print(mycolors.reset + "".ljust(23) + ja3, end='\n')
                    if ('modules_loaded' in vttext['data']):
                        print(mycolors.foreground.yellow + "\nModules Loaded: ", end='')
                        for module in vttext['data']['modules_loaded']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(module, width=120))), end=' ')
                    if ('registry_keys_opened' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nRegistry Keys Opened: ", end='')
                        for key in vttext['data']['registry_keys_opened']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(key, width=120))), end=' ')
                    if ('files_opened' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nFiles Opened: ", end='')
                        for filename in vttext['data']['files_opened']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filename, width=120))), end=' ')
                    if ('files_written' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nFiles Written: ", end='')
                        for filewritten in vttext['data']['files_written']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filewritten, width=120))), end=' ')
                    if ('files_deleted' in vttext['data']):
                        print(mycolors.foreground.lightcyan + "\n\nFiles Deleted: ", end='')
                        for filedeleted in vttext['data']['files_deleted']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filedeleted, width=120))), end=' ')
                    if ('command_executions' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nCommand Executions: ", end='')
                        for command in vttext['data']['command_executions']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(command, width=120))), end=' ')
                    if ('mutexes_created' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nMutex Created: ", end='')
                        for mutex in vttext['data']['mutexes_created']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(mutex, width=120))), end=' ')
                    if ('windows_hidden' in vttext['data']):
                        print(mycolors.foreground.yellow + "\n\nWindows Hidden: ", end='\n')
                        for windows_hidden in vttext['data']['windows_hidden']:
                            print(mycolors.reset + "".ljust(23) + windows_hidden, end='\n')

                if (cv.bkg == 0):
                    finalhash = myhash
                    print(mycolors.foreground.red + "\nProvided Hash: ".ljust(24) + mycolors.reset + finalhash)
                    if ('verdicts' in vttext['data']):
                        print(mycolors.foreground.purple + "Verdicts: ".ljust(22) + mycolors.reset, end=' ')
                        for verdict in vttext['data']['verdicts']:
                            print(mycolors.reset + (verdict), end=' | ')
                    if ('verdict_confidence' in vttext['data']):
                        print(mycolors.foreground.purple + "\nVerdict Confidence: ".ljust(24) + mycolors.reset + str(vttext['data']['verdict_confidence']) + mycolors.reset, end=' ')
                    if ('verdict_labels' in vttext['data']):
                        print(mycolors.foreground.purple + "\nVerdict Labels: ".ljust(23) + mycolors.reset, end=' ')
                        for label in vttext['data']['verdict_labels']:
                            print(mycolors.reset + (label), end=' ')
                    if ('processes_injected' in vttext['data']):
                        print(mycolors.foreground.red + "\n\nProcesses Injected: ", end='')
                        for injected in vttext['data']['processes_injected']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(injected, width=120))), end=' ')
                    if ('calls_highlighted' in vttext['data']):
                        print(mycolors.foreground.red + "\n\nCalls Highlighted: ", end='')
                        for calls in vttext['data']['calls_highlighted']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(calls, width=120))), end=' ')
                    if ('processes_tree' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nProcesses Tree: ", end='')
                        for process in vttext['data']['processes_tree']:
                            print("\n")
                            print(mycolors.reset + " ".ljust(23) + "process_id: ".ljust(15) + process['process_id'], end='')
                            print(mycolors.reset + ("\n".ljust(24) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(39)).join(textwrap.wrap(" ".join(process['name'].split()), width=80))), end=' ')
                            if ('children' in process):
                                print(mycolors.reset + "\n".ljust(24) + "children: ".ljust(15), end='')
                                for child in process['children']:
                                    print(mycolors.reset + "\n".ljust(28) + "process_id: ".ljust(15) + child['process_id'], end='')
                                    print(mycolors.reset + ("\n".ljust(28) + "process_name: ".ljust(15) + mycolors.reset + (mycolors.reset + "\n".ljust(43)).join(textwrap.wrap(" ".join(child['name'].split()), width=80))), end=' ')
                    if ('processes_terminated' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nProcesses Terminated: ", end='\n')
                        for process_term in vttext['data']['processes_terminated']:
                            print(mycolors.reset + "".ljust(23) + process_term, end='\n')
                    if ('processes_killed' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nProcesses Killed: ", end='\n')
                        for process_kill in vttext['data']['processes_killed']:
                            print(mycolors.reset + "".ljust(23) + process_kill, end='\n')
                    if ('services_created' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nServices Created: ", end='\n')
                        for services_created in vttext['data']['services_created']:
                            print(mycolors.reset + "".ljust(23) + services_created, end='\n')
                    if ('services_deleted' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nServices Deleted: ", end='\n')
                        for services_deleted in vttext['data']['services_deleted']:
                            print(mycolors.reset + "".ljust(23) + services_deleted, end='\n')
                    if ('services_started' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nServices Started: ", end='\n')
                        for services_started in vttext['data']['services_started']:
                            print(mycolors.reset + "".ljust(23) + services_started, end='\n')
                    if ('services_stopped' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nServices Stopped: ", end='\n')
                        for services_stopped in vttext['data']['services_stopped']:
                            print(mycolors.reset + "".ljust(23) + services_stopped, end='\n')
                    if ('dns_lookups' in vttext['data']):
                        print(mycolors.foreground.blue + "\nDNS Lookups: ", end='')
                        for lookup in vttext['data']['dns_lookups']:
                            if ('resolved_ips' in lookup):
                                print(mycolors.reset + "\n".ljust(24) + "resolved_ips: ", end='')
                                for ip in (lookup['resolved_ips']):
                                    print(ip, end=' | ')
                            if ('hostname' in lookup):
                                print(mycolors.reset + "\n".ljust(24) + "hostname: ".ljust(14) + lookup['hostname'], end='\n')
                    if ('ja3_digests' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nJA3 Digests: ", end='\n')
                        for ja3 in vttext['data']['ja3_digests']:
                            print(mycolors.reset + "".ljust(23) + ja3, end='\n')
                    if ('modules_loaded' in vttext['data']):
                        print(mycolors.foreground.blue + "\nModules Loaded: ", end='')
                        for module in vttext['data']['modules_loaded']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(module, width=120))), end=' ')
                    if ('registry_keys_opened' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nRegistry Keys Opened: ", end='')
                        for key in vttext['data']['registry_keys_opened']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(key, width=120))), end=' ')
                    if ('files_opened' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nFiles Opened: ", end='')
                        for filename in vttext['data']['files_opened']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filename, width=120))), end=' ')
                    if ('files_written' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nFiles Written: ", end='')
                        for filewritten in vttext['data']['files_written']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filewritten, width=120))), end=' ')
                    if ('files_deleted' in vttext['data']):
                        print(mycolors.foreground.blue + "\n\nFiles Deleted: ", end='')
                        for filedeleted in vttext['data']['files_deleted']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(filedeleted, width=120))), end=' ')
                    if ('command_executions' in vttext['data']):
                        print(mycolors.foreground.purple + "\n\nCommand Executions: ", end='')
                        for command in vttext['data']['command_executions']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(command, width=120))), end=' ')
                    if ('mutexes_created' in vttext['data']):
                        print(mycolors.foreground.purple + "\n\nMutex Created: ", end='')
                        for mutex in vttext['data']['mutexes_created']:
                            print(mycolors.reset + ("\n".ljust(24) + ("\n" + "".ljust(24)).join(textwrap.wrap(mutex, width=120))), end=' ')
                    if ('windows_hidden' in vttext['data']):
                        print(mycolors.foreground.purple + "\n\nWindows Hidden: ", end='\n')
                        for windows_hidden in vttext['data']['windows_hidden']:
                            print(mycolors.reset + "".ljust(23) + windows_hidden, end='\n')

                all_tags = []
                for key in ('verdict_labels', 'verdicts', 'calls_highlighted'):
                    if key in vttext['data']:
                        all_tags.extend(vttext['data'][key])
                for technique in vttext['data'].get('mitre_attack_techniques', []):
                    if isinstance(technique, dict) and technique.get('id'):
                        all_tags.append(technique['id'])
                map_and_display(all_tags, label='VirusTotal Behavior')

        except ValueError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Virus Total!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Virus Total!\n"))
            print(mycolors.reset)
            exit(3)

    def vtdirchecking(self, repo2, apitype):
        F = []
        H = []
        type_description = ''
        threat_label = ''
        malicious = ''
        apitype_var = apitype

        directory = repo2
        if not os.path.isabs(directory):
            directory = os.path.abspath('.') + "/" + directory
        os.chdir(directory)

        try:
            for filen in os.listdir(directory):
                try:
                    filename = str(filen)
                    if os.path.isdir(filename):
                        continue
                    F.append(filename)
                    H.append(sha256hash(filename))

                except (AttributeError, NameError):
                    if (cv.bkg == 1):
                        print(mycolors.foreground.lightred + "\nAn error has occured while reading the %s file." % filename)
                    else:
                        print(mycolors.foreground.red + "\nAn error has occured while reading the %s file." % filename)
                    print(mycolors.reset)

            file_hash_dict = dict(list(zip(F, H)))

            header = ("Sample".ljust(9) + "Filename".ljust(72) + "Description".ljust(30)
                      + "Threat Label".ljust(34) + "AV".ljust(4) + "Overlay".center(9) + "Ent")
            print("\n" + mycolors.foreground.neutral(cv.bkg) + header + mycolors.reset)
            print(divider(display_width(header)), end="\n\n")

            hashnumber = 0

            for key, value in file_hash_dict.items():
                hashnumber = hashnumber + 1
                (type_description, threat_label, malicious) = self.vtbatchwork(value)
                try:
                    magictype = ftype(key)
                except Exception:
                    magictype = ''
                if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
                    try:
                        overlay = isoverlay(key)
                    except Exception:
                        overlay = "N/A"
                else:
                    overlay = "N/A"
                entropy = "%.2f" % fileentropy(key)
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + ("file_" + str(hashnumber)).ljust(9) + mycolors.reset + (key.strip()).ljust(72) + mycolors.foreground.yellow + (type_description).ljust(30) + mycolors.foreground.lightcyan + (threat_label).ljust(34) + mycolors.foreground.lightred + str(malicious).ljust(4) + mycolors.foreground.yellow + overlay.center(9) + mycolors.foreground.lightcyan + entropy)
                if (cv.bkg == 0):
                    print(mycolors.foreground.blue + ("file_" + str(hashnumber)).ljust(9) + mycolors.reset + (key.strip()).ljust(72) + mycolors.foreground.blue + (type_description).ljust(30) + mycolors.foreground.blue + (threat_label).ljust(34) + mycolors.foreground.red + str(malicious).ljust(4) + mycolors.foreground.blue + overlay.center(9) + mycolors.foreground.blue + entropy)
                if (apitype_var == 1):
                    if ((hashnumber % 4) == 0):
                        time.sleep(61)
        except OSError:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "The provided file doesn't exist!\n"))
            else:
                print((mycolors.foreground.red + "The provided file doesn't exist!\n"))
            print(mycolors.reset)
            exit(3)

    @cached("vt_hash")
    def _raw_hash_info(self, hash_value):
        try:
            url = 'https://www.virustotal.com/api/v3/files/'
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            response = requestsession.get(url + hash_value)
            if response.status_code == 200:
                return strip_json_escapes(response.json())
        except Exception:
            pass
        return None

    def _vthunterror(self, message):
        if is_text_output():
            print(mycolors.foreground.error(cv.bkg) + "\n" + message + "\n" + mycolors.reset)

    def _vttrim(self, value, width):
        text = str(value)
        if len(text) > width:
            return text[:max(width - 3, 0)] + '...'
        return text

    def _vthuntdate(self, value):
        if value in (None, ''):
            return 'N/A'
        try:
            return str(datetime.fromtimestamp(int(value)))
        except (TypeError, ValueError, OSError, OverflowError):
            return 'N/A'

    def _vtcountrules(self, rulestext):
        if not rulestext:
            return 0
        return len(re.findall(r'(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+', rulestext))

    def _vtreadhuntrules(self, rulespath):
        if not rulespath:
            self._vthunterror("You didn't provide a YARA rules file or a directory containing YARA rules.")
            return (None, None)

        rulesfiles = []

        if os.path.isdir(rulespath):
            for root, dirs, files in os.walk(rulespath):
                dirs.sort()
                for filename in sorted(files):
                    if filename.lower().endswith(('.yar', '.yara')):
                        rulesfiles.append(os.path.join(root, filename))
            rulesfiles.sort()
            if not rulesfiles:
                self._vthunterror("No .yar or .yara files were found under the %s directory." % rulespath)
                return (None, None)
        elif os.path.isfile(rulespath):
            rulesfiles.append(rulespath)
        else:
            self._vthunterror("The provided YARA rules path (%s) doesn't exist." % rulespath)
            return (None, None)

        chunks = []
        for rulesfile in rulesfiles:
            try:
                with open(rulesfile, 'r', encoding='utf-8', errors='replace') as fh:
                    chunks.append(fh.read())
            except OSError:
                self._vthunterror("An error has occurred while reading the %s YARA rules file." % rulesfile)
                return (None, None)

        rulestext = "\n".join(chunks)
        rulesbytes = len(rulestext.encode('utf-8', errors='replace'))
        rulescount = self._vtcountrules(rulestext)

        if rulesbytes == 0:
            self._vthunterror("The provided YARA rules path (%s) is empty." % rulespath)
            return (None, None)

        if rulesbytes > VirusTotalExtractor.HUNT_MAX_RULES_BYTES:
            self._vthunterror("The YARA rules text collected from %s is %s (%d bytes), which exceeds the %s (%d bytes) accepted by VirusTotal. Reduce the rules and try again." % (rulespath, humansize(rulesbytes), rulesbytes, humansize(VirusTotalExtractor.HUNT_MAX_RULES_BYTES), VirusTotalExtractor.HUNT_MAX_RULES_BYTES))
            return (None, None)

        if rulescount > VirusTotalExtractor.HUNT_MAX_RULES:
            self._vthunterror("The YARA rules text collected from %s holds %d rule definitions, which exceeds the limit of %d rules accepted by VirusTotal. Reduce the number of rules and try again." % (rulespath, rulescount, VirusTotalExtractor.HUNT_MAX_RULES))
            return (None, None)

        label = os.path.basename(os.path.normpath(rulespath))
        label = os.path.splitext(label)[0]
        label = re.sub(r'[^A-Za-z0-9_.-]', '_', label)
        if not label:
            label = 'malwoverview_ruleset'

        return (rulestext, label)

    def _vtintelerror(self, response, action):
        if response.status_code in (200, 201):
            return False

        detail = ''
        try:
            body = strip_json_escapes(response.json())
            if isinstance(body, dict):
                detail = str(body.get('error', {}).get('message', ''))
        except Exception:
            detail = ''

        if (response.status_code == 401):
            message = "VirusTotal rejected your API key (401) while trying to %s. Check the VTAPI entry of your .malwapi.conf file." % action
        elif (response.status_code == 403):
            message = "VirusTotal answered 403 (forbidden) while trying to %s. The /intelligence/ endpoints used by Retrohunt and Livehunt require premium (enterprise) privileges, so your API key almost certainly doesn't have premium privileges enabled." % action
        elif (response.status_code == 429):
            message = "VirusTotal answered 429 while trying to %s, which means your request quota has been exceeded. Wait until your quota is restored and try again." % action
        elif (response.status_code == 404):
            message = "VirusTotal answered 404 (not found) while trying to %s. Check whether the provided identifier is correct." % action
        else:
            message = "VirusTotal answered HTTP %d while trying to %s." % (response.status_code, action)

        if detail:
            message = message + " VirusTotal message: " + detail

        self._vthunterror(message)
        return True

    def vtretrohuntsubmit(self, rulespath, corpus='main', notification_email=None):
        self.requestVTAPI()

        rulestext = self._vtreadhuntrules(rulespath)[0]
        if rulestext is None:
            return False

        corpusvalue = str(corpus or 'main').strip().lower()
        if corpusvalue not in VirusTotalExtractor.RETROHUNT_CORPUS:
            self._vthunterror("The corpus must be either main or goodware, but %s was provided." % corpus)
            return False

        attributes = {'rules': rulestext, 'corpus': corpusvalue}
        if notification_email:
            attributes['notification_email'] = str(notification_email)

        payload = {'data': {'type': 'retrohunt_job', 'attributes': attributes}}

        try:
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.post(VirusTotalExtractor.urlretrohuntvt3, json=payload)

            if self._vtintelerror(response, "create a retrohunt job"):
                return False

            vttext = strip_json_escapes(json.loads(response.text))
            data = vttext.get('data', {})
            attrs = data.get('attributes', {})

            jobid = str(data.get('id', 'N/A'))
            rulescount = self._vtcountrules(rulestext)
            rulesbytes = len(rulestext.encode('utf-8', errors='replace'))

            record = {
                'source': 'VirusTotal Retrohunt',
                'job_id': jobid,
                'status': str(attrs.get('status', 'N/A')),
                'corpus': str(attrs.get('corpus', corpusvalue)),
                'rules_path': str(rulespath),
                'rules_count': rulescount,
                'rules_size': rulesbytes,
                'notification_email': str(attrs.get('notification_email', notification_email or 'N/A')),
                'creation_date': self._vthuntdate(attrs.get('creation_date'))
            }
            collector.add(record)

            if is_text_output():
                fields = [
                    ('Job ID', jobid),
                    ('Status', record['status']),
                    ('Corpus', record['corpus']),
                    ('Rules Path', record['rules_path']),
                    ('Rule Definitions', str(rulescount)),
                    ('Rules Size', humansize(rulesbytes)),
                    ('Notification', record['notification_email']),
                    ('Creation Date', record['creation_date'])
                ]

                print("")
                if (cv.bkg == 1):
                    for (fieldname, fieldvalue) in fields:
                        print(mycolors.foreground.lightcyan + (fieldname + ": ").ljust(22) + mycolors.reset + str(fieldvalue))
                    print(mycolors.foreground.yellow + "\nThe retrohunt job has been created. Check its progress with the retrohunt status option and the job id above.")
                    print(mycolors.foreground.yellow + "Matches are capped at 10000 files per job. " + VirusTotalExtractor.HUNT_SIZE_NOTE)
                    print(mycolors.foreground.yellow + "The size of the scanned time window depends on your account tier (Hunting Pro accounts scan a longer window than standard accounts).")
                if (cv.bkg == 0):
                    for (fieldname, fieldvalue) in fields:
                        print(mycolors.foreground.blue + (fieldname + ": ").ljust(22) + mycolors.reset + str(fieldvalue))
                    print(mycolors.foreground.purple + "\nThe retrohunt job has been created. Check its progress with the retrohunt status option and the job id above.")
                    print(mycolors.foreground.purple + "Matches are capped at 10000 files per job. " + VirusTotalExtractor.HUNT_SIZE_NOTE)
                    print(mycolors.foreground.purple + "The size of the scanned time window depends on your account tier (Hunting Pro accounts scan a longer window than standard accounts).")
                printr()

            return True

        except ValueError:
            self._vthunterror("An error has occurred while parsing the VirusTotal answer to the retrohunt job creation.")
        except requests.exceptions.RequestException as e:
            self._vthunterror("An error has occurred while connecting to VirusTotal: %s" % str(e))
        except Exception as e:
            self._vthunterror("An error has occurred while creating the retrohunt job: %s" % str(e))

        return False

    def vtretrohuntlist(self, statusfilter=None, limit=10):
        self.requestVTAPI()

        try:
            limitvalue = int(limit)
        except (TypeError, ValueError):
            limitvalue = 10
        if limitvalue < 1:
            limitvalue = 1

        params = {'limit': limitvalue}

        if statusfilter:
            statusvalue = str(statusfilter).strip().lower()
            if statusvalue.startswith('status:'):
                statusvalue = statusvalue.split(':', 1)[1].strip()
            if statusvalue not in VirusTotalExtractor.RETROHUNT_STATUS:
                self._vthunterror("The status filter must be one of the following: %s." % ", ".join(VirusTotalExtractor.RETROHUNT_STATUS))
                return False
            params['filter'] = 'status:' + statusvalue

        try:
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(VirusTotalExtractor.urlretrohuntvt3, params=params)

            if self._vtintelerror(response, "list the retrohunt jobs"):
                return False

            vttext = strip_json_escapes(json.loads(response.text))
            jobs = vttext.get('data', [])
            if not isinstance(jobs, list):
                jobs = []

            if not jobs:
                self._vthunterror("No retrohunt jobs have been found for the provided criteria.")
                return True

            rows = []
            for job in jobs:
                if not isinstance(job, dict):
                    continue
                attrs = job.get('attributes', {})
                progress = attrs.get('progress', 0)
                try:
                    progresstext = "%.2f%%" % float(progress)
                except (TypeError, ValueError):
                    progresstext = 'N/A'
                matches = attrs.get('num_matches', 0)
                try:
                    matchesvalue = int(matches)
                except (TypeError, ValueError):
                    matchesvalue = 0

                row = {
                    'source': 'VirusTotal Retrohunt',
                    'job_id': str(job.get('id', 'N/A')),
                    'status': str(attrs.get('status', 'N/A')),
                    'progress': progresstext,
                    'num_matches': matchesvalue,
                    'corpus': str(attrs.get('corpus', 'N/A')),
                    'creation_date': self._vthuntdate(attrs.get('creation_date'))
                }
                rows.append(row)
                collector.add(row)

            if is_text_output():
                idwidth = max([len("Job ID")] + [len(row['job_id']) for row in rows]) + 2

                print("")
                print("Job ID".ljust(idwidth) + "Status".ljust(12) + "Progress".ljust(11) + "Matches".ljust(10) + "Created")
                print('-' * (idwidth + 53), end="\n\n")

                for row in rows:
                    status = row['status']
                    if (cv.bkg == 1):
                        if (status == 'finished'):
                            statuscolor = mycolors.foreground.lightgreen
                        elif (status in ('aborted', 'aborting')):
                            statuscolor = mycolors.foreground.lightred
                        else:
                            statuscolor = mycolors.foreground.yellow
                        matchescolor = mycolors.foreground.lightred if (row['num_matches'] > 0) else mycolors.reset
                        print(mycolors.foreground.lightcyan + row['job_id'].ljust(idwidth) + statuscolor + status.ljust(12) + mycolors.foreground.yellow + row['progress'].ljust(11) + matchescolor + str(row['num_matches']).ljust(10) + mycolors.reset + row['creation_date'] + mycolors.reset)
                    if (cv.bkg == 0):
                        if (status == 'finished'):
                            statuscolor = mycolors.foreground.blue
                        elif (status in ('aborted', 'aborting')):
                            statuscolor = mycolors.foreground.red
                        else:
                            statuscolor = mycolors.foreground.blue
                        matchescolor = mycolors.foreground.red if (row['num_matches'] > 0) else mycolors.reset
                        print(mycolors.foreground.blue + row['job_id'].ljust(idwidth) + statuscolor + status.ljust(12) + mycolors.foreground.blue + row['progress'].ljust(11) + matchescolor + str(row['num_matches']).ljust(10) + mycolors.reset + row['creation_date'] + mycolors.reset)
                printr()

            return True

        except ValueError:
            self._vthunterror("An error has occurred while parsing the VirusTotal answer to the retrohunt job listing.")
        except requests.exceptions.RequestException as e:
            self._vthunterror("An error has occurred while connecting to VirusTotal: %s" % str(e))
        except Exception as e:
            self._vthunterror("An error has occurred while listing the retrohunt jobs: %s" % str(e))

        return False

    def vtretrohuntstatus(self, jobid):
        self.requestVTAPI()

        if not jobid:
            self._vthunterror("You didn't provide a retrohunt job id.")
            return False

        try:
            finalurl = ''.join([VirusTotalExtractor.urlretrohuntvt3, "/", quote(str(jobid).strip(), safe='')])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl)

            if self._vtintelerror(response, "get the status of the retrohunt job %s" % jobid):
                return False

            vttext = strip_json_escapes(json.loads(response.text))
            data = vttext.get('data', {})
            attrs = data.get('attributes', {})

            progress = attrs.get('progress', 0)
            try:
                progresstext = "%.2f%%" % float(progress)
            except (TypeError, ValueError):
                progresstext = 'N/A'

            etaseconds = attrs.get('eta_seconds')
            if etaseconds in (None, ''):
                etatext = 'N/A'
            else:
                try:
                    etatext = "%d seconds" % int(etaseconds)
                except (TypeError, ValueError):
                    etatext = 'N/A'

            scannedbytes = attrs.get('scanned_bytes')
            scannedtext = 'N/A' if scannedbytes in (None, '') else humansize(scannedbytes)

            record = {
                'source': 'VirusTotal Retrohunt',
                'job_id': str(data.get('id', jobid)),
                'status': str(attrs.get('status', 'N/A')),
                'progress': progresstext,
                'num_matches': attrs.get('num_matches', 0),
                'num_matches_outside_time_range': attrs.get('num_matches_outside_time_range', 0),
                'eta_seconds': etatext,
                'scanned_bytes': scannedtext,
                'corpus': str(attrs.get('corpus', 'N/A')),
                'notification_email': str(attrs.get('notification_email', 'N/A')),
                'creation_date': self._vthuntdate(attrs.get('creation_date')),
                'start_date': self._vthuntdate(attrs.get('start_date')),
                'finish_date': self._vthuntdate(attrs.get('finish_date')),
                'rule_definitions': self._vtcountrules(attrs.get('rules', ''))
            }
            collector.add(record)

            if is_text_output():
                fields = [
                    ('Job ID', record['job_id']),
                    ('Status', record['status']),
                    ('Progress', record['progress']),
                    ('Matches', str(record['num_matches'])),
                    ('Matches Outside', str(record['num_matches_outside_time_range'])),
                    ('ETA', record['eta_seconds']),
                    ('Scanned Bytes', record['scanned_bytes']),
                    ('Corpus', record['corpus']),
                    ('Rule Definitions', str(record['rule_definitions'])),
                    ('Notification', record['notification_email']),
                    ('Creation Date', record['creation_date']),
                    ('Start Date', record['start_date']),
                    ('Finish Date', record['finish_date'])
                ]

                print("")
                if (cv.bkg == 1):
                    for (fieldname, fieldvalue) in fields:
                        print(mycolors.foreground.lightcyan + (fieldname + ": ").ljust(22) + mycolors.reset + str(fieldvalue))
                if (cv.bkg == 0):
                    for (fieldname, fieldvalue) in fields:
                        print(mycolors.foreground.blue + (fieldname + ": ").ljust(22) + mycolors.reset + str(fieldvalue))
                printr()

            return True

        except ValueError:
            self._vthunterror("An error has occurred while parsing the VirusTotal answer to the retrohunt job status.")
        except requests.exceptions.RequestException as e:
            self._vthunterror("An error has occurred while connecting to VirusTotal: %s" % str(e))
        except Exception as e:
            self._vthunterror("An error has occurred while getting the retrohunt job status: %s" % str(e))

        return False

    def vtretrohuntmatches(self, jobid, limit=10):
        self.requestVTAPI()

        if not jobid:
            self._vthunterror("You didn't provide a retrohunt job id.")
            return False

        try:
            limitvalue = int(limit)
        except (TypeError, ValueError):
            limitvalue = 10
        if limitvalue < 1:
            limitvalue = 1

        try:
            finalurl = ''.join([VirusTotalExtractor.urlretrohuntvt3, "/", quote(str(jobid).strip(), safe=''), "/matching_files"])
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(finalurl, params={'limit': limitvalue})

            if self._vtintelerror(response, "get the matching files of the retrohunt job %s" % jobid):
                return False

            vttext = strip_json_escapes(json.loads(response.text))
            matches = vttext.get('data', [])
            if not isinstance(matches, list):
                matches = []

            if not matches:
                self._vthunterror("No matching files have been found for the retrohunt job %s." % jobid)
                return True

            rows = []
            for match in matches:
                if not isinstance(match, dict):
                    continue
                attrs = match.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious = 0
                if isinstance(stats, dict) and stats:
                    try:
                        malicious = int(stats.get('malicious', 0))
                    except (TypeError, ValueError):
                        malicious = 0
                    total = sum(value for value in stats.values() if isinstance(value, int))
                    detection = str(malicious) + "/" + str(total)
                else:
                    detection = 'N/A'

                filesize = attrs.get('size')
                row = {
                    'source': 'VirusTotal Retrohunt',
                    'job_id': str(jobid),
                    'sha256': str(attrs.get('sha256', match.get('id', 'N/A'))),
                    'file_type': str(attrs.get('type_description', attrs.get('type_tag', 'N/A'))),
                    'size': 'N/A' if filesize in (None, '') else humansize(filesize),
                    'detection': detection,
                    'malicious': malicious
                }
                rows.append(row)
                collector.add(row)

            if is_text_output():
                print("")
                header = ("SHA256".ljust(66) + "File Type".ljust(30) + "Size".ljust(14)
                          + "Detection")
                print(mycolors.foreground.neutral(cv.bkg) + header + mycolors.reset)
                print(divider(display_width(header)), end="\n\n")

                for row in rows:
                    filetype = self._vttrim(row['file_type'], 28)
                    if (cv.bkg == 1):
                        detcolor = mycolors.foreground.lightred if (row['malicious'] > 0) else mycolors.foreground.lightgreen
                        print(mycolors.foreground.lightcyan + row['sha256'].ljust(66) + mycolors.foreground.yellow + filetype.ljust(30) + mycolors.reset + row['size'].ljust(14) + detcolor + row['detection'] + mycolors.reset)
                    if (cv.bkg == 0):
                        detcolor = mycolors.foreground.red if (row['malicious'] > 0) else mycolors.foreground.blue
                        print(mycolors.foreground.blue + row['sha256'].ljust(66) + mycolors.foreground.blue + filetype.ljust(30) + mycolors.reset + row['size'].ljust(14) + detcolor + row['detection'] + mycolors.reset)
                printr()

            return True

        except ValueError:
            self._vthunterror("An error has occurred while parsing the VirusTotal answer to the retrohunt matching files.")
        except requests.exceptions.RequestException as e:
            self._vthunterror("An error has occurred while connecting to VirusTotal: %s" % str(e))
        except Exception as e:
            self._vthunterror("An error has occurred while getting the retrohunt matching files: %s" % str(e))

        return False

    def vtlivehuntcreate(self, rulespath, name=None, enabled=True, match_object_type='file'):
        self.requestVTAPI()

        (rulestext, label) = self._vtreadhuntrules(rulespath)
        if rulestext is None:
            return False

        matchtype = str(match_object_type or 'file').strip().lower()
        if matchtype not in VirusTotalExtractor.HUNT_MATCH_TYPES:
            self._vthunterror("The match object type must be one of the following: %s." % ", ".join(VirusTotalExtractor.HUNT_MATCH_TYPES))
            return False

        rulesetname = str(name).strip() if name else label
        if not rulesetname:
            rulesetname = label

        payload = {
            'data': {
                'type': 'hunting_ruleset',
                'attributes': {
                    'name': rulesetname,
                    'enabled': bool(enabled),
                    'rules': rulestext,
                    'match_object_type': matchtype
                }
            }
        }

        try:
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.post(VirusTotalExtractor.urlhuntrulesetvt3, json=payload)

            if self._vtintelerror(response, "create a livehunt ruleset"):
                return False

            vttext = strip_json_escapes(json.loads(response.text))
            data = vttext.get('data', {})
            attrs = data.get('attributes', {})

            rulescount = self._vtcountrules(rulestext)
            rulesbytes = len(rulestext.encode('utf-8', errors='replace'))

            record = {
                'source': 'VirusTotal Livehunt',
                'ruleset_id': str(data.get('id', 'N/A')),
                'name': str(attrs.get('name', rulesetname)),
                'enabled': 'YES' if attrs.get('enabled', bool(enabled)) else 'NO',
                'match_object_type': str(attrs.get('match_object_type', matchtype)),
                'rules_path': str(rulespath),
                'rules_count': rulescount,
                'rules_size': rulesbytes,
                'creation_date': self._vthuntdate(attrs.get('creation_date'))
            }
            collector.add(record)

            if is_text_output():
                fields = [
                    ('Ruleset ID', record['ruleset_id']),
                    ('Name', record['name']),
                    ('Enabled', record['enabled']),
                    ('Match Object Type', record['match_object_type']),
                    ('Rules Path', record['rules_path']),
                    ('Rule Definitions', str(rulescount)),
                    ('Rules Size', humansize(rulesbytes)),
                    ('Creation Date', record['creation_date'])
                ]

                print("")
                if (cv.bkg == 1):
                    for (fieldname, fieldvalue) in fields:
                        print(mycolors.foreground.lightcyan + (fieldname + ": ").ljust(22) + mycolors.reset + str(fieldvalue))
                    print(mycolors.foreground.yellow + "\nThe livehunt ruleset has been created and it will be applied to the files submitted to VirusTotal from now on.")
                    print(mycolors.foreground.yellow + VirusTotalExtractor.HUNT_SIZE_NOTE)
                if (cv.bkg == 0):
                    for (fieldname, fieldvalue) in fields:
                        print(mycolors.foreground.blue + (fieldname + ": ").ljust(22) + mycolors.reset + str(fieldvalue))
                    print(mycolors.foreground.purple + "\nThe livehunt ruleset has been created and it will be applied to the files submitted to VirusTotal from now on.")
                    print(mycolors.foreground.purple + VirusTotalExtractor.HUNT_SIZE_NOTE)
                printr()

            return True

        except ValueError:
            self._vthunterror("An error has occurred while parsing the VirusTotal answer to the livehunt ruleset creation.")
        except requests.exceptions.RequestException as e:
            self._vthunterror("An error has occurred while connecting to VirusTotal: %s" % str(e))
        except Exception as e:
            self._vthunterror("An error has occurred while creating the livehunt ruleset: %s" % str(e))

        return False

    def vtlivehuntlist(self, limit=10):
        self.requestVTAPI()

        try:
            limitvalue = int(limit)
        except (TypeError, ValueError):
            limitvalue = 10
        if limitvalue < 1:
            limitvalue = 1

        try:
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(VirusTotalExtractor.urlhuntrulesetvt3, params={'limit': limitvalue})

            if self._vtintelerror(response, "list the livehunt rulesets"):
                return False

            vttext = strip_json_escapes(json.loads(response.text))
            rulesets = vttext.get('data', [])
            if not isinstance(rulesets, list):
                rulesets = []

            if not rulesets:
                self._vthunterror("No livehunt rulesets have been found for your account.")
                return True

            rows = []
            for ruleset in rulesets:
                if not isinstance(ruleset, dict):
                    continue
                attrs = ruleset.get('attributes', {})
                rulestext = attrs.get('rules', '')
                rulescount = attrs.get('number_of_rules')
                if rulescount in (None, ''):
                    rulescount = self._vtcountrules(rulestext)

                row = {
                    'source': 'VirusTotal Livehunt',
                    'ruleset_id': str(ruleset.get('id', 'N/A')),
                    'name': str(attrs.get('name', 'N/A')),
                    'enabled': 'YES' if attrs.get('enabled') else 'NO',
                    'rules_count': rulescount,
                    'rules_size': humansize(len(str(rulestext).encode('utf-8', errors='replace'))),
                    'creation_date': self._vthuntdate(attrs.get('creation_date'))
                }
                rows.append(row)
                collector.add(row)

            if is_text_output():
                idwidth = max([len("Ruleset ID")] + [len(row['ruleset_id']) for row in rows]) + 2

                print("")
                print("Ruleset ID".ljust(idwidth) + "Name".ljust(33) + "Enabled".ljust(9) + "Rules".ljust(7) + "Size".ljust(12) + "Created")
                print('-' * (idwidth + 81), end="\n\n")

                for row in rows:
                    rulesetname = self._vttrim(row['name'], 31)
                    if (cv.bkg == 1):
                        enabledcolor = mycolors.foreground.lightgreen if (row['enabled'] == 'YES') else mycolors.foreground.lightred
                        print(mycolors.foreground.lightcyan + row['ruleset_id'].ljust(idwidth) + mycolors.reset + rulesetname.ljust(33) + enabledcolor + row['enabled'].ljust(9) + mycolors.foreground.yellow + str(row['rules_count']).ljust(7) + mycolors.foreground.lightcyan + row['rules_size'].ljust(12) + mycolors.reset + row['creation_date'] + mycolors.reset)
                    if (cv.bkg == 0):
                        enabledcolor = mycolors.foreground.blue if (row['enabled'] == 'YES') else mycolors.foreground.red
                        print(mycolors.foreground.blue + row['ruleset_id'].ljust(idwidth) + mycolors.reset + rulesetname.ljust(33) + enabledcolor + row['enabled'].ljust(9) + mycolors.foreground.blue + str(row['rules_count']).ljust(7) + mycolors.foreground.blue + row['rules_size'].ljust(12) + mycolors.reset + row['creation_date'] + mycolors.reset)
                printr()

            return True

        except ValueError:
            self._vthunterror("An error has occurred while parsing the VirusTotal answer to the livehunt ruleset listing.")
        except requests.exceptions.RequestException as e:
            self._vthunterror("An error has occurred while connecting to VirusTotal: %s" % str(e))
        except Exception as e:
            self._vthunterror("An error has occurred while listing the livehunt rulesets: %s" % str(e))

        return False

    def vtlivehuntnotifications(self, limit=10):
        self.requestVTAPI()

        try:
            limitvalue = int(limit)
        except (TypeError, ValueError):
            limitvalue = 10
        if limitvalue < 1:
            limitvalue = 1

        try:
            requestsession = create_session()
            requestsession.headers.update({'x-apikey': self.VTAPI})
            requestsession.headers.update({'content-type': 'application/json'})
            response = requestsession.get(VirusTotalExtractor.urlhuntnotificationfilesvt3, params={'limit': limitvalue})

            if self._vtintelerror(response, "list the livehunt notifications"):
                return False

            vttext = strip_json_escapes(json.loads(response.text))
            notifications = vttext.get('data', [])
            if not isinstance(notifications, list):
                notifications = []

            if not notifications:
                self._vthunterror("No livehunt notifications have been found for your account.")
                return True

            rows = []
            for notification in notifications:
                if not isinstance(notification, dict):
                    continue
                attrs = notification.get('attributes', {})
                context = notification.get('context_attributes', {})
                if not isinstance(context, dict):
                    context = {}
                rulename = context.get('rule_name') or context.get('ruleset_name') or 'N/A'
                row = {
                    'source': 'VirusTotal Livehunt',
                    'notification_id': str(context.get('notification_id', 'N/A')),
                    'rule_name': str(rulename),
                    'sha256': str(attrs.get('sha256') or notification.get('id', 'N/A')),
                    'date': self._vthuntdate(context.get('notification_date'))
                }
                rows.append(row)
                collector.add(row)

            if is_text_output():
                print("")
                header = "Rule Name".ljust(33) + "SHA256".ljust(66) + "Date"
                print(mycolors.foreground.neutral(cv.bkg) + header + mycolors.reset)
                print(divider(display_width(header)), end="\n\n")

                for row in rows:
                    rulename = self._vttrim(row['rule_name'], 31)
                    if (cv.bkg == 1):
                        print(mycolors.foreground.yellow + rulename.ljust(33) + mycolors.foreground.lightcyan + row['sha256'].ljust(66) + mycolors.reset + row['date'] + mycolors.reset)
                    if (cv.bkg == 0):
                        print(mycolors.foreground.blue + rulename.ljust(33) + mycolors.foreground.blue + row['sha256'].ljust(66) + mycolors.reset + row['date'] + mycolors.reset)
                printr()

            return True

        except ValueError:
            self._vthunterror("An error has occurred while parsing the VirusTotal answer to the livehunt notifications.")
        except requests.exceptions.RequestException as e:
            self._vthunterror("An error has occurred while connecting to VirusTotal: %s" % str(e))
        except Exception as e:
            self._vthunterror("An error has occurred while listing the livehunt notifications: %s" % str(e))

        return False
