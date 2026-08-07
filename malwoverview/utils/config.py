import os

import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors


SERVICE_MAP = {
    'virustotal': ('VIRUSTOTAL', 'VTAPI'),
    'hybrid': ('HYBRID-ANALYSIS', 'HAAPI'),
    'malshare': ('MALSHARE', 'MALSHAREAPI'),
    'urlhaus': ('URLHAUS', 'URLHAUSAPI'),
    'polyswarm': ('POLYSWARM', 'POLYAPI'),
    'alienvault': ('ALIENVAULT', 'ALIENAPI'),
    'malpedia': ('MALPEDIA', 'MALPEDIAAPI'),
    'triage': ('TRIAGE', 'TRIAGEAPI'),
    'ipinfo': ('IPINFO', 'IPINFOAPI'),
    'bazaar': ('BAZAAR', 'BAZAARAPI'),
    'threatfox': ('THREATFOX', 'THREATFOXAPI'),
    'vulncheck': ('VULNCHECK', 'VULNCHECKAPI'),
    'shodan': ('SHODAN', 'SHODANAPI'),
    'abuseipdb': ('ABUSEIPDB', 'ABUSEIPDBAPI'),
    'greynoise': ('GREYNOISE', 'GREYNOISEAPI'),
    'urlscanio': ('URLSCANIO', 'URLSCANIOAPI'),
}


def redact_secret(text, secret, placeholder='[REDACTED]'):
    text = str(text)
    if secret:
        text = text.replace(secret, placeholder)
    return text


def validate_config(operation, config_dict):
    if operation in SERVICE_MAP:
        section, key = SERVICE_MAP[operation]
        if section in config_dict and config_dict[section].get(key):
            return True
        print(
            f"{mycolors.foreground.warning(cv.bkg)}"
            f"Warning: API key for {operation} is not configured in .malwapi.conf"
            f"{mycolors.reset}"
        )
        return False
    return True


def check_config_permissions(config_path):
    if os.name == 'nt':
        return
    try:
        mode = os.stat(config_path).st_mode
    except OSError:
        return
    if mode & 0o077:
        print(
            f"{mycolors.foreground.warning(cv.bkg)}"
            f"Warning: {config_path} is accessible to other users "
            f"(permissions {oct(mode & 0o777)[2:]}) and it stores API keys. "
            f"Restrict it with: chmod 600 {config_path}"
            f"{mycolors.reset}"
        )
