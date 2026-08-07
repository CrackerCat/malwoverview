import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr, strip_json_escapes, divider
import requests
import textwrap
import base64
import json
import os
from urllib.parse import quote
from malwoverview.utils.session import create_session, failure_message
from malwoverview.utils.output import collector, is_text_output, add_records

SAMPLE_RECORD_WIDTH = 75
FAMILY_RECORD_WIDTH = 112


class MalpediaExtractor():
    malpediaurl = 'https://malpedia.caad.fkie.fraunhofer.de/api'

    TLP_LEVELS = {
        'white': 'tlp_white',
        'tlp_white': 'tlp_white',
        'green': 'tlp_green',
        'tlp_green': 'tlp_green',
        'amber': 'tlp_amber',
        'tlp_amber': 'tlp_amber',
        'auto': 'auto'
    }

    def __init__(self, MALPEDIAAPI):
        self.MALPEDIAAPI = MALPEDIAAPI

    def requestMALPEDIAAPI(self):
        if (self.MALPEDIAAPI == ''):
            print(mycolors.foreground.red + "\nTo be able to get information from Malpedia, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Malpedia API according to the format shown on the Github website." + mycolors.reset + "\n")
            exit(1)

    def malpedia_actors(self):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''

        self.requestMALPEDIAAPI()

        try:

            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'list', 'actors'])
            haresponse = requestsession.get(url=finalurl)
            hatext = strip_json_escapes(json.loads(haresponse.text))
            add_records('malpedia', 'malpedia_actors', hatext)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                print(mycolors.foreground.lightcyan + "\nActors:".ljust(13), end='\n'.ljust(11))
                j = 1
                for i in hatext:
                    if (j < 10):
                        print(mycolors.foreground.lightred + "Actor_%s:    " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if ((j > 9) and (j < 100)):
                        print(mycolors.foreground.lightred + "Actor_%s:   " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if (j > 99):
                        print(mycolors.foreground.lightred + "Actor_%s:  " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    j = j + 1

            if (cv.bkg == 0):
                print(mycolors.foreground.green + "\nActors:".ljust(13), end='\n'.ljust(11))
                j = 1
                for i in hatext:
                    if (j < 10):
                        print(mycolors.foreground.red + "Actor_%s:    " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if ((j > 9) and (j < 100)):
                        print(mycolors.foreground.red + "Actor_%s:   " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if (j > 99):
                        print(mycolors.foreground.red + "Actor_%s:  " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    j = j + 1

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'Malpedia'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_payloads(self):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''

        self.requestMALPEDIAAPI()

        try:

            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'list', 'samples'])
            haresponse = requestsession.get(url=finalurl)
            hatext = strip_json_escapes(json.loads(haresponse.text))
            add_records('malpedia', 'malpedia_payloads', hatext)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                for key, value in hatext.items():
                    print(mycolors.foreground.yellow + "Family:".ljust(11) + mycolors.reset + key, end=' ')
                    for i in value:
                        for j in i.items():
                            for k in i.keys():
                                if (k == 'status'):
                                    if (i['status']):
                                        print(mycolors.foreground.lightcyan + "\n\nStatus:".ljust(13) + mycolors.reset + str(i['status']), end='')
                                if (k == 'sha256'):
                                    if (i['sha256']):
                                        print(mycolors.foreground.lightcyan + "\nHash:".ljust(12) + mycolors.reset + str(i['sha256']), end='')
                                if (k == 'version'):
                                    if (i['version']):
                                        print(mycolors.foreground.lightcyan + "\nVersion:".ljust(12) + mycolors.reset + str(i['version']), end=' ')
                    print("\n" + divider(SAMPLE_RECORD_WIDTH))

            if (cv.bkg == 0):
                for key, value in hatext.items():
                    print(mycolors.foreground.red + "Family:".ljust(11) + mycolors.reset + key, end=' ')
                    for i in value:
                        for j in i.items():
                            for k in i.keys():
                                if (k == 'status'):
                                    if (i['status']):
                                        print(mycolors.foreground.green + "\n\nStatus:".ljust(13) + mycolors.reset + str(i['status']), end='')
                                if (k == 'sha256'):
                                    if (i['sha256']):
                                        print(mycolors.foreground.green + "\nHash:".ljust(12) + mycolors.reset + str(i['sha256']), end='')
                                if (k == 'version'):
                                    if (i['version']):
                                        print(mycolors.foreground.green + "\nVersion:".ljust(12) + mycolors.reset + str(i['version']), end=' ')
                    print("\n" + divider(SAMPLE_RECORD_WIDTH))
        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'Malpedia'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_actor(self, arg1):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myargs = arg1
        wrapper = textwrap.TextWrapper(width=100)

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'actor', quote(myargs, safe='')])
            haresponse = requestsession.get(url=finalurl)
            hatext = strip_json_escapes(json.loads(haresponse.text))
            add_records('malpedia', 'malpedia_get_actor', hatext)

            if (cv.bkg == 1):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.yellow + "\nInformation about this actor couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if (cv.bkg == 0):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.blue + "\nInformation about this actor couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                if (hatext['value']):
                    print(mycolors.foreground.yellow + "\nActor:".ljust(11) + mycolors.reset + hatext['value'], end=' ')
                if (hatext['description']):
                    print(mycolors.foreground.yellow + "\n\nOverview: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(hatext['description']), width=100)), end=' ')
                for key, value in hatext.items():
                    if (key == 'meta'):
                        for key2, value2 in value.items():
                            if (key2 == 'country'):
                                if (value['country']):
                                    print(mycolors.foreground.yellow + "\n\nCountry:".ljust(12) + mycolors.reset + str(value['country']), end='\n')
                            if (key2 == 'synonyms'):
                                if (value['synonyms']):
                                    print(mycolors.foreground.lightcyan + "\n\nSynonyms:".ljust(11), end=' ')
                                    for x in value['synonyms']:
                                        print(mycolors.reset + str(x), end=' ')
                            if (key2 == 'refs'):
                                if (value['refs']):
                                    for x in value['refs']:
                                        print(mycolors.foreground.lightcyan + "\nREFs:".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(x))).ljust(11), end=" ")
                    if (key == 'families'):
                        for key3, value3 in value.items():
                            print("\n" + divider(FAMILY_RECORD_WIDTH), end='')
                            print(mycolors.foreground.yellow + "\nFamily: ".ljust(11) + mycolors.reset + key3)
                            if 'updated' in value3.keys():
                                if (value3['updated']):
                                    print(mycolors.foreground.lightcyan + "Updated: ".ljust(10) + mycolors.reset + value3['updated'])
                            if 'attribution' in value3.keys():
                                if (len(value3['attribution']) > 0):
                                    print(mycolors.foreground.lightcyan + "Attrib.: ".ljust(9), end=' ')
                                    for y in value3['attribution']:
                                        print(mycolors.reset + y, end=' ')
                            if 'alt_names' in value3.keys():
                                if (len(value3['alt_names']) > 0):
                                    print(mycolors.foreground.lightcyan + "\nAliases: ".ljust(10), end=' ')
                                    for y in value3['alt_names']:
                                        print(mycolors.reset + y, end=' ')
                            if 'common_name' in value3.keys():
                                if (value3['common_name']):
                                    print(mycolors.foreground.lightcyan + "\nCommon: ".ljust(11) + mycolors.reset + value3['common_name'], end=' ')
                            if 'sources' in value3.keys():
                                if (len(value3['sources']) > 0):
                                    print(mycolors.foreground.lightcyan + "\nSources: ".ljust(11), end=' ')
                                    for y in value3['sources']:
                                        print(mycolors.reset + y, end=' ')
                            if 'description' in value3.keys():
                                if value3['description']:
                                    print(mycolors.foreground.lightcyan + "\nDescr.: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(value3['description']), width=100)), end=' ')
                            if 'urls' in value3.keys():
                                if (len(value3['urls']) > 0):
                                    for y in value3['urls']:
                                        print(mycolors.foreground.lightcyan + "\nURLs: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(y))).ljust(11), end=" ")

            if (cv.bkg == 0):
                if (hatext['value']):
                    print(mycolors.foreground.red + "\nActor:".ljust(11) + mycolors.reset + hatext['value'], end=' ')
                if (hatext['description']):
                    print(mycolors.foreground.red + "\n\nOverview: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(hatext['description']), width=100)), end=' ')
                for key, value in hatext.items():
                    if (key == 'meta'):
                        for key2, value2 in value.items():
                            if (key2 == 'country'):
                                if (value['country']):
                                    print(mycolors.foreground.red + "\n\nCountry:".ljust(12) + mycolors.reset + str(value['country']), end='\n')
                            if (key2 == 'synonyms'):
                                if (value['synonyms']):
                                    print(mycolors.foreground.green + "\n\nSynonyms:".ljust(11), end=' ')
                                    for x in value['synonyms']:
                                        print(mycolors.reset + str(x), end=' ')
                            if (key2 == 'refs'):
                                if (value['refs']):
                                    for x in value['refs']:
                                        print(mycolors.foreground.green + "\nREFs:".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(x))).ljust(11), end=" ")
                    if (key == 'families'):
                        for key3, value3 in value.items():
                            print("\n" + divider(FAMILY_RECORD_WIDTH), end='')
                            print(mycolors.foreground.red + "\nFamily: ".ljust(11) + mycolors.reset + key3)
                            if 'updated' in value3.keys():
                                if (value3['updated']):
                                    print(mycolors.foreground.green + "Updated: ".ljust(10) + mycolors.reset + value3['updated'])
                            if 'attribution' in value3.keys():
                                if (len(value3['attribution']) > 0):
                                    print(mycolors.foreground.green + "Attrib.: ".ljust(9), end=' ')
                                    for y in value3['attribution']:
                                        print(mycolors.reset + y, end=' ')
                            if 'alt_names' in value3.keys():
                                if (len(value3['alt_names']) > 0):
                                    print(mycolors.foreground.green + "\nAliases: ".ljust(10), end=' ')
                                    for y in value3['alt_names']:
                                        print(mycolors.reset + y, end=' ')
                            if 'common_name' in value3.keys():
                                if (value3['common_name']):
                                    print(mycolors.foreground.green + "\nCommon: ".ljust(11) + mycolors.reset + value3['common_name'], end=' ')
                            if 'sources' in value3.keys():
                                if (len(value3['sources']) > 0):
                                    print(mycolors.foreground.green + "\nSources: ".ljust(11), end=' ')
                                    for y in value3['sources']:
                                        print(mycolors.reset + y, end=' ')
                            if 'description' in value3.keys():
                                if value3['description']:
                                    print(mycolors.foreground.green + "\nDescr.: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(textwrap.wrap(str(value3['description']), width=100)), end=' ')
                            if 'urls' in value3.keys():
                                if (len(value3['urls']) > 0):
                                    for y in value3['urls']:
                                        print(mycolors.foreground.green + "\nURLs: ".ljust(11) + mycolors.reset + ("\n".ljust(11)).join(wrapper.wrap(str(y))).ljust(11), end=" ")

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'Malpedia'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_families_meta(self, arg1=None):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myfilter = str(arg1).strip().lower() if arg1 else ''

        MAX_DESC = 400
        MAX_ITEMS = 8
        SEPWIDTH = 112

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'families'])
            haresponse = requestsession.get(url=finalurl)
            hatext = strip_json_escapes(json.loads(haresponse.text))

            if ('200' not in str(haresponse)):
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nThe meta information for all families couldn't be retrieved from Malpedia.\n", mycolors.reset)
                return

            if isinstance(hatext, dict):
                families = list(hatext.items())
            elif isinstance(hatext, list):
                families = []
                for entry in hatext:
                    if isinstance(entry, dict):
                        families.append((str(entry.get('id') or entry.get('family_id') or entry.get('common_name') or ''), entry))
                    else:
                        families.append((str(entry), {}))
            else:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nUnexpected response format received from Malpedia.\n", mycolors.reset)
                return

            def aslist(value):
                if not value:
                    return []
                if isinstance(value, (list, tuple, set)):
                    return [str(x) for x in value if x]
                return [str(value)]

            def capped(values):
                if (len(values) > MAX_ITEMS):
                    return values[:MAX_ITEMS] + ["(+%d more)" % (len(values) - MAX_ITEMS)]
                return values

            if is_text_output():
                print("\n" + (mycolors.reset + "MALPEDIA FAMILIES META INFORMATION".center(SEPWIDTH)))

            shown = 0
            for famid, meta in sorted(families, key=lambda x: str(x[0]).lower()):
                famid = str(famid)
                if not isinstance(meta, dict):
                    meta = {}

                common = str(meta.get('common_name') or '')
                altnames = aslist(meta.get('alt_names'))
                attribution = aslist(meta.get('attribution'))
                sources = aslist(meta.get('sources'))
                urls = aslist(meta.get('urls'))
                updated = str(meta.get('updated') or '')
                description = str(meta.get('description') or '')

                if myfilter:
                    haystack = ' '.join([famid, common] + altnames).lower()
                    if (myfilter not in haystack):
                        continue

                collector.add({
                    'family_id': famid,
                    'common_name': common,
                    'alt_names': altnames,
                    'attribution': attribution,
                    'sources': sources,
                    'updated': updated,
                    'description': description,
                    'urls': urls
                })

                shown = shown + 1

                if not is_text_output():
                    continue

                shortdesc = description
                if (len(shortdesc) > MAX_DESC):
                    shortdesc = shortdesc[:MAX_DESC].rstrip() + '...'

                if (cv.bkg == 1):
                    print("\n" + ('-' * SEPWIDTH))
                    print(mycolors.foreground.lightcyan + "Family:".ljust(13) + mycolors.reset + famid)
                    if (common):
                        print(mycolors.foreground.yellow + "Common Name:".ljust(13) + mycolors.reset + common)
                    if (updated):
                        print(mycolors.foreground.yellow + "Updated:".ljust(13) + mycolors.reset + updated)
                    if (altnames):
                        print(mycolors.foreground.yellow + "Aliases:".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(', '.join(capped(altnames)), width=95)))
                    if (attribution):
                        print(mycolors.foreground.yellow + "Attribution:".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(', '.join(capped(attribution)), width=95)))
                    if (sources):
                        print(mycolors.foreground.yellow + "Sources:".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(', '.join(capped(sources)), width=95)))
                    if (shortdesc):
                        print(mycolors.foreground.yellow + "Description:".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(shortdesc, width=95)))
                    if (urls):
                        print(mycolors.foreground.yellow + "URLs:".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(capped(urls)))
                else:
                    print("\n" + ('-' * SEPWIDTH))
                    print(mycolors.foreground.purple + "Family:".ljust(13) + mycolors.foreground.blue + famid)
                    if (common):
                        print(mycolors.foreground.blue + "Common Name:".ljust(13) + mycolors.foreground.blue + common)
                    if (updated):
                        print(mycolors.foreground.blue + "Updated:".ljust(13) + mycolors.foreground.blue + updated)
                    if (altnames):
                        print(mycolors.foreground.blue + "Aliases:".ljust(13) + mycolors.foreground.blue + ("\n".ljust(14)).join(textwrap.wrap(', '.join(capped(altnames)), width=95)))
                    if (attribution):
                        print(mycolors.foreground.blue + "Attribution:".ljust(13) + mycolors.foreground.blue + ("\n".ljust(14)).join(textwrap.wrap(', '.join(capped(attribution)), width=95)))
                    if (sources):
                        print(mycolors.foreground.blue + "Sources:".ljust(13) + mycolors.foreground.blue + ("\n".ljust(14)).join(textwrap.wrap(', '.join(capped(sources)), width=95)))
                    if (shortdesc):
                        print(mycolors.foreground.blue + "Description:".ljust(13) + mycolors.foreground.blue + ("\n".ljust(14)).join(textwrap.wrap(shortdesc, width=95)))
                    if (urls):
                        print(mycolors.foreground.blue + "URLs:".ljust(13) + mycolors.foreground.blue + ("\n".ljust(14)).join(capped(urls)))

            if is_text_output():
                print("\n" + ('-' * SEPWIDTH))
                if (shown == 0):
                    print(mycolors.foreground.error(cv.bkg) + "\nNo family matched the provided filter: %s\n" % myfilter, mycolors.reset)
                elif (myfilter):
                    print(mycolors.foreground.info(cv.bkg) + "\nFamilies shown: ".ljust(13) + mycolors.reset + "%d (filter: %s) out of %d tracked by Malpedia." % (shown, myfilter, len(families)))
                else:
                    print(mycolors.foreground.info(cv.bkg) + "\nFamilies shown: ".ljust(13) + mycolors.reset + "%d" % shown)
                printr()

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'Malpedia'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_families(self):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        # wrapper = textwrap.TextWrapper(width=100)

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'list', 'families'])
            haresponse = requestsession.get(url=finalurl)
            hatext = strip_json_escapes(json.loads(haresponse.text))
            add_records('malpedia', 'malpedia_families', hatext)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                print(mycolors.foreground.yellow + "\nFamilies:".ljust(13), end='\n'.ljust(11))
                j = 1
                for i in hatext:
                    if (j < 10):
                        print(mycolors.foreground.lightcyan + "Family_%s:     " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if ((j > 9) and (j < 100)):
                        print(mycolors.foreground.lightcyan + "Family_%s:    " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if ((j > 99) and (j < 1000)):
                        print(mycolors.foreground.lightcyan + "Family_%s:   " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if (j > 999):
                        print(mycolors.foreground.lightcyan + "Family_%s:  " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    j = j + 1

            if (cv.bkg == 0):
                print(mycolors.foreground.red + "\nFamilies:".ljust(13), end='\n'.ljust(11))
                j = 1
                for i in hatext:
                    if (j < 10):
                        print(mycolors.foreground.blue + "Family_%s:     " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if ((j > 9) and (j < 100)):
                        print(mycolors.foreground.blue + "Family_%s:    " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if ((j > 99) and (j < 1000)):
                        print(mycolors.foreground.blue + "Family_%s:   " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    if (j > 999):
                        print(mycolors.foreground.blue + "Family_%s:  " % j + mycolors.reset + str(i), end='\n'.ljust(11))
                    j = j + 1

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'Malpedia'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_family(self, arg1):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myargs = arg1
        # wrapper = textwrap.TextWrapper(width=100)

        self.requestMALPEDIAAPI()

        try:

            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'family', quote(myargs, safe='')])
            haresponse = requestsession.get(url=finalurl)
            hatext = strip_json_escapes(json.loads(haresponse.text))
            add_records('malpedia', 'malpedia_get_family', hatext)

            if (cv.bkg == 1):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.yellow + "\nInformation about this family couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if (cv.bkg == 0):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.blue + "\nInformation about this family couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if (cv.bkg == 1):
                print(mycolors.foreground.lightcyan + "\nFamily:".ljust(14) + mycolors.reset + myargs)
                print(mycolors.foreground.yellow + "\nUpdated:".ljust(14) + mycolors.reset + hatext['updated'], end=' ')
                if (hatext['attribution']):
                    print(mycolors.foreground.yellow + "\nAttribution:".ljust(13), end=' ')
                    for i in hatext['attribution']:
                        print(mycolors.reset + str(i), end=' ')
                if (hatext['alt_names']):
                    print(mycolors.foreground.yellow + "\nAliases:".ljust(13), end=' ')
                    for i in hatext['alt_names']:
                        print(mycolors.reset + i, end=' ')
                if (hatext['common_name']):
                    print(mycolors.foreground.yellow + "\nCommon Name: ".ljust(13) + mycolors.reset + hatext['common_name'], end=' ')
                if (hatext['description']):
                    print(mycolors.foreground.yellow + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['description'], width=110)), end='\n')

                if (hatext['urls']):
                    j = 0
                    for i in hatext['urls']:
                        if (j < 10):
                            print(mycolors.foreground.yellow + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        if (j > 9 and j < 100):
                            print(mycolors.foreground.yellow + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        if (j > 99):
                            print(mycolors.foreground.yellow + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        j = j + 1

            if (cv.bkg == 0):
                print(mycolors.foreground.purple + "\nFamily:".ljust(14) + mycolors.reset + myargs)
                print(mycolors.foreground.blue + "\nUpdated:".ljust(14) + mycolors.reset + hatext['updated'], end=' ')
                if (hatext['attribution']):
                    print(mycolors.foreground.blue + "\nAttribution:".ljust(13), end=' ')
                    for i in hatext['attribution']:
                        print(mycolors.reset + str(i), end=' ')
                if (hatext['alt_names']):
                    print(mycolors.foreground.blue + "\nAliases:".ljust(13), end=' ')
                    for i in hatext['alt_names']:
                        print(mycolors.reset + i, end=' ')
                if (hatext['common_name']):
                    print(mycolors.foreground.blue + "\nCommon Name: ".ljust(13) + mycolors.reset + hatext['common_name'], end=' ')
                if (hatext['description']):
                    print(mycolors.foreground.blue + "\nDescription: ".ljust(13) + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(hatext['description'], width=110)), end='\n')

                if (hatext['urls']):
                    j = 0
                    for i in hatext['urls']:
                        if (j < 10):
                            print(mycolors.foreground.blue + "\nURL_%d:".ljust(15) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        if (j > 9 and j < 100):
                            print(mycolors.foreground.blue + "\nURL_%d:".ljust(14) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        if (j > 99):
                            print(mycolors.foreground.blue + "\nURL_%d:".ljust(13) % j + mycolors.reset + ("\n".ljust(14)).join(textwrap.wrap(i, width=110)), end=' ')
                        j = j + 1

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'Malpedia'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_sample(self, arg1):
        if len(arg1) not in [32, 64]:
            return False

        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myargs = arg1

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'sample', quote(myargs, safe=''), 'zip'])
            haresponse = requestsession.get(url=finalurl)
            hatext = strip_json_escapes(json.loads(haresponse.text))
            add_records('malpedia', 'malpedia_get_sample', hatext)

            if (cv.bkg == 1):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.yellow + "\nThis sample couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if (cv.bkg == 0):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.blue + "\nThis sample couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if ('200' in str(haresponse)):
                safe_filename = os.path.basename(myargs) + ".zip"
                outputpath = os.path.join(cv.output_dir, safe_filename)
                with open(outputpath, 'wb') as f:
                    f.write(base64.b64decode(hatext['zipped']))
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + f"\nSample downloaded to: {outputpath}\n", mycolors.reset)
                else:
                    print(mycolors.foreground.green + f"\nSample downloaded to: {outputpath}\n", mycolors.reset)
                return

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'Malpedia'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_yara(self, arg1):
        urlx = MalpediaExtractor.malpediaurl

        hatext = ''
        haresponse = ''
        myargs = arg1

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'yara', quote(myargs, safe=''), 'zip'])
            haresponse = requestsession.get(url=finalurl)

            if (cv.bkg == 1):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.yellow + "\nThe Yara rule for this family couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if (cv.bkg == 0):
                if ('Not found.' in str(hatext)):
                    print(mycolors.foreground.blue + "\nThe Yara rule for this family couldn't be found on Malpedia.\n", mycolors.reset)
                    exit(1)

            if ('200' not in str(haresponse)):
                print(mycolors.foreground.red + "\nThe search key couldn't be found on Malpedia.\n", mycolors.reset)
                exit(1)

            if ('200' in str(haresponse)):
                safe_filename = os.path.basename(myargs) + ".zip"
                outputpath = os.path.join(cv.output_dir, safe_filename)
                if (cv.bkg == 1):
                    with open(outputpath, 'wb') as f:
                        f.write(haresponse.content)
                        collector.add({'service': 'malpedia', 'query_type': 'malpedia_get_yara', 'query': arg1, 'file': outputpath, 'size': os.path.getsize(outputpath)})
                    print(mycolors.foreground.lightcyan + "\nA zip file named %s.zip containing Yara rules has been SUCCESSFULLY downloaded from Malpedia!\n" % myargs, mycolors.reset)
                else:
                    with open(outputpath, 'wb') as f:
                        f.write(haresponse.content)
                        collector.add({'service': 'malpedia', 'query_type': 'malpedia_get_yara', 'query': arg1, 'file': outputpath, 'size': os.path.getsize(outputpath)})
                    print(mycolors.foreground.green + "\nA zip file named %s.zip containing Yara rules has been SUCCESSFULLY downloaded from Malpedia!\n" % myargs, mycolors.reset)
                return
        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'Malpedia'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Malpedia!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Malpedia!\n"))
            printr()

    def malpedia_get_yara_ruleset(self, arg1):
        urlx = MalpediaExtractor.malpediaurl

        haresponse = ''
        requested = str(arg1).strip().lower() if arg1 else ''
        tlplevel = MalpediaExtractor.TLP_LEVELS.get(requested)

        MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024

        if (tlplevel is None):
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + "\nInvalid Malpedia YARA ruleset level: %s" % (requested if requested else '(empty)'), mycolors.reset)
                print(mycolors.foreground.error(cv.bkg) + "Valid values are: tlp_white, tlp_green, tlp_amber and auto (short forms accepted: white, green, amber).\n", mycolors.reset)
            return

        self.requestMALPEDIAAPI()

        try:
            resource = urlx
            requestsession = create_session()
            requestsession.headers.update({'Content-Type': 'application/json'})
            requestsession.headers.update({'Authorization': 'apitoken ' + self.MALPEDIAAPI})
            finalurl = '/'.join([resource, 'get', 'yara', tlplevel, 'zip'])
            haresponse = requestsession.get(url=finalurl, stream=True)

            if (haresponse.status_code == 401):
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nMalpedia rejected the API token (401). Check the MALPEDIAAPI value in your .malwapi.conf file.\n", mycolors.reset)
                return

            if (haresponse.status_code == 403):
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nMalpedia denied access (403) to the %s ruleset. Your API token most likely does not have permission for this TLP level. Request a higher access level from Malpedia or retry with tlp_white.\n" % tlplevel, mycolors.reset)
                return

            if (haresponse.status_code == 404):
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nMalpedia has no ruleset available at %s (404).\n" % finalurl, mycolors.reset)
                return

            if (haresponse.status_code != 200):
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nMalpedia returned HTTP %d while downloading the %s ruleset. Check your connection, the API token and https://malpedia.caad.fkie.fraunhofer.de/usage/api for the service status.\n" % (haresponse.status_code, tlplevel), mycolors.reset)
                return

            content = bytearray()
            for chunk in haresponse.iter_content(chunk_size=8192):
                if chunk:
                    content += chunk
                    if len(content) > MAX_DOWNLOAD_SIZE:
                        if is_text_output():
                            print(mycolors.foreground.error(cv.bkg) + "\nError: the Malpedia YARA ruleset exceeded 100MB. Download aborted.\n", mycolors.reset)
                        return

            if not content:
                if is_text_output():
                    print(mycolors.foreground.error(cv.bkg) + "\nMalpedia returned an empty response for the %s ruleset.\n" % tlplevel, mycolors.reset)
                return

            safe_filename = 'malpedia_yara_' + tlplevel + '.zip'
            outputpath = os.path.join(cv.output_dir, safe_filename)
            with open(outputpath, 'wb') as f:
                f.write(content)

            collector.add({
                'source': 'malpedia_yara_ruleset',
                'ruleset': tlplevel,
                'size': len(content),
                'path': outputpath
            })

            if is_text_output():
                if (cv.bkg == 1):
                    print(mycolors.foreground.lightcyan + "\nRuleset:".ljust(14) + mycolors.reset + tlplevel)
                    print(mycolors.foreground.yellow + "Size:".ljust(13) + mycolors.reset + "%d bytes" % len(content))
                    print(mycolors.foreground.yellow + "Saved to:".ljust(13) + mycolors.reset + outputpath)
                else:
                    print(mycolors.foreground.purple + "\nRuleset:".ljust(14) + mycolors.foreground.blue + tlplevel)
                    print(mycolors.foreground.blue + "Size:".ljust(13) + mycolors.foreground.blue + "%d bytes" % len(content))
                    print(mycolors.foreground.blue + "Saved to:".ljust(13) + mycolors.foreground.blue + outputpath)
                printr()

        except (ValueError, requests.exceptions.RequestException):
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg)
                      + "\nMalpedia did not return the YARA ruleset. Building the whole TLP set is slow and the "
                        "endpoint frequently answers 504 or drops the connection; retry in a few minutes.\n"
                      + mycolors.reset)
            printr()
