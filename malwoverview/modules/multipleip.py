from malwoverview.utils.colors import mycolors, printr, printc, strip_json_escapes, bullet, report_header
from malwoverview.utils.output import collector, is_text_output
import malwoverview.modules.configvars as cv

IP_TABLE_WIDTH = 100


class MultipleIPExtractor:
    METHODS = {
        "IPInfo": 'get_ip_details',
        "Shodan": 'shodan_ip',
        "AbuseIPDB": 'check_ip',
        "GreyNoise": 'quick_check',
    }

    def __init__(self, extractors):
        self.extractors = extractors

    def get_multiple_ip_details(self, ip_address):
        if ip_address is None:
            printc("A valid IP address is required.", mycolors.foreground.error(cv.bkg))
            return

        for name, extractor_obj in self.extractors.items():
            try:
                if name == "VirusTotal":
                    data = extractor_obj._raw_ip_info(ip_address)
                    self._get_info_virustotal(strip_json_escapes(data.json()))
                elif name == "AlienVault":
                    data = extractor_obj._raw_ip_info(ip_address)
                    self._get_info_alienvault(strip_json_escapes(data.json()))
                else:
                    method = MultipleIPExtractor.METHODS.get(name)
                    if method and hasattr(extractor_obj, method):
                        getattr(extractor_obj, method)(ip_address)
            except Exception as e:
                printc(f"\n{name} error: {str(e)}\n", mycolors.foreground.error(cv.bkg))

    def _get_info_virustotal(self, data):
        try:
            attributes = data.get('data', {}).get('attributes', {})

            fields = {
                'Reputation': attributes.get('reputation'),
                'RIR': attributes.get('regional_internet_registry'),
                'Network': attributes.get('network'),
                'ASN': attributes.get('asn'),
                'AS Owner': attributes.get('as_owner'),
                'Country Code': attributes.get('country'),
                'Continent': attributes.get('continent')
            }

            stats = attributes.get('last_analysis_stats', {})
            votes = attributes.get('total_votes', {})

            record = {'service': 'virustotal'}
            for field, value in fields.items():
                record[field.lower().replace(' ', '_')] = value
            for stat, count in stats.items():
                record['stat_' + stat] = count
            for vote, count in votes.items():
                record['votes_' + vote] = count
            collector.add(record)

            if not is_text_output():
                return

            print()
            print(report_header("VIRUSTOTAL IP REPORT", IP_TABLE_WIDTH))

            COLSIZE = max(len(field) for field in fields.keys()) + 3

            for field, value in fields.items():
                print(mycolors.foreground.info(cv.bkg) + f"{field}:".ljust(COLSIZE) + "\t" + mycolors.reset + str(value))

            print("\nAnalysis Stats:")
            for stat, count in stats.items():
                print(mycolors.foreground.error(cv.bkg) + f"{stat.title()}:".ljust(COLSIZE) + "\t" + mycolors.reset + str(count))

            print("\nCommunity Votes:")
            for vote, count in votes.items():
                print(mycolors.foreground.error(cv.bkg) + f"{vote.title()}:".ljust(COLSIZE) + "\t" + mycolors.reset + str(count))

        except Exception as e:
            if is_text_output():
                print(mycolors.foreground.error(cv.bkg) + f"\nError: {str(e)}\n" + mycolors.reset)

        if is_text_output():
            print()
            print(bullet("For the full VirusTotal report use the -v and -V options.",
                         IP_TABLE_WIDTH))

    def _get_info_alienvault(self, data):
        try:
            collector.add({
                'service': 'alienvault',
                'asn': data.get('asn'),
                'country': data.get('country_name'),
                'region': data.get('region'),
                'city': data.get('city'),
                'continent': data.get('continent_code'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'sections': ', '.join(data.get('sections', [])),
                'pulses': data.get('pulse_info', {}).get('count'),
            })

            if not is_text_output():
                return

            print()
            print(report_header("ALIENVAULT IP REPORT", IP_TABLE_WIDTH))

            COLSIZE = 13

            infocolor = mycolors.foreground.info(cv.bkg)
            print(infocolor + f"ASN:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('asn')))
            print(infocolor + f"Country:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('country_name')))
            print(infocolor + f"Region:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('region')))
            print(infocolor + f"City:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('city')))
            print(infocolor + f"Continent:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('continent_code')))
            print(infocolor + f"Latitude:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('latitude')))
            print(infocolor + f"Longitude:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('longitude')))
            print(infocolor + f"Sections:".ljust(COLSIZE) + "\t" + mycolors.reset + ', '.join(data.get('sections', [])))
            print(mycolors.foreground.error(cv.bkg) + f"Pulses Found:".ljust(COLSIZE) + "\t" + mycolors.reset + str(data.get('pulse_info', {}).get('count')))
                
        except Exception as e:
            if is_text_output():
                printc(f"\nError: {str(e)}\n", mycolors.foreground.error(cv.bkg))

        if is_text_output():
            print()
            print(bullet("For the full AlienVault report use the -n and -N options.",
                         IP_TABLE_WIDTH))