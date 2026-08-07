import json
import os
import re
import time
from difflib import SequenceMatcher
from pathlib import Path

from malwoverview.utils.colors import mycolors, strip_terminal_escapes
import malwoverview.modules.configvars as cv
from malwoverview.utils.output import collector, is_text_output
from malwoverview.utils.session import create_session


ATTACK_URL = (
    'https://raw.githubusercontent.com/mitre/cti/master/'
    'enterprise-attack/enterprise-attack.json'
)
CACHE_FILE = os.path.join(str(Path.home()), '.malwoverview_attack.json')
CACHE_MAX_AGE = 7 * 24 * 3600  # 7 days

MIN_TAG_LENGTH = 4
MIN_ALIAS_LENGTH = 8
MAX_MATCHES_PER_TAG = 3
MAX_MATCHES_TOTAL = 30
FUZZY_MIN_LENGTH = 8
FUZZY_MIN_RATIO = 0.90
ID_COLUMN_WIDTH = 15
NAME_COLUMN_WIDTH = 56
NAME_MATCH_EXCLUDED_TACTICS = frozenset(['reconnaissance', 'resource-development'])

MATCH_BY_ID = 0
MATCH_BY_NAME = 1
MATCH_BY_ALIAS = 2
MATCH_BY_FUZZY = 3

_MATCH_LABELS = {
    MATCH_BY_ID: 'technique_id',
    MATCH_BY_NAME: 'technique_name',
    MATCH_BY_ALIAS: 'name_segment',
    MATCH_BY_FUZZY: 'fuzzy_name',
}

_ID_TOKEN_RE = re.compile(
    r'(?<![0-9A-Za-z])T\d{4}(?:\.\d{3})?(?![0-9A-Za-z])',
    re.IGNORECASE
)
_NON_ALNUM_RE = re.compile(r'[^0-9a-z]+')

_bundle = None
_bundle_failed = False
_error_reported = False
_mapper = None


def _squash(text):
    return _NON_ALNUM_RE.sub('', str(text).lower())


def _shorten(text, width):
    if len(text) <= width:
        return text
    return text[:width - 4] + '...'


def _report_error(message):
    global _error_reported
    if _error_reported:
        return
    _error_reported = True
    if not is_text_output() or cv.verbosity < 0:
        return
    print(mycolors.foreground.error(cv.bkg) + message + mycolors.reset)


def _parse_bundle(data):
    techniques = {}
    name_index = {}
    alias_index = {}
    for obj in data.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue
        technique_id = ''
        url = ''
        for ref in obj.get('external_references', []):
            if not isinstance(ref, dict):
                continue
            if ref.get('source_name') != 'mitre-attack':
                continue
            technique_id = str(ref.get('external_id', '')).strip().upper()
            url = strip_terminal_escapes(str(ref.get('url', '')))
            break
        if not technique_id or not _ID_TOKEN_RE.fullmatch(technique_id):
            continue
        kill_chain = []
        for phase in obj.get('kill_chain_phases', []):
            if not isinstance(phase, dict):
                continue
            phase_name = strip_terminal_escapes(str(phase.get('phase_name', '')))
            if phase_name and phase_name not in kill_chain:
                kill_chain.append(phase_name)
        name = strip_terminal_escapes(str(obj.get('name', '')))
        techniques[technique_id] = {
            'name': name,
            'description': obj.get('description', ''),
            'kill_chain_phases': kill_chain,
            'url': url,
        }
        if kill_chain and not set(kill_chain) - NAME_MATCH_EXCLUDED_TACTICS:
            continue
        key = _squash(name)
        if len(key) >= MIN_TAG_LENGTH:
            name_index.setdefault(key, [])
            if technique_id not in name_index[key]:
                name_index[key].append(technique_id)
        if '/' in name:
            for segment in name.split('/'):
                alias = _squash(segment)
                if len(alias) < MIN_ALIAS_LENGTH:
                    continue
                alias_index.setdefault(alias, [])
                if technique_id not in alias_index[alias]:
                    alias_index[alias].append(technique_id)
    for key in list(alias_index):
        if key in name_index:
            del alias_index[key]
    return techniques, name_index, alias_index


def _read_cache():
    try:
        if not os.path.exists(CACHE_FILE):
            return None
        age = time.time() - os.path.getmtime(CACHE_FILE)
        if age >= CACHE_MAX_AGE:
            return None
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return None
    if not isinstance(data, dict) or not isinstance(data.get('objects'), list):
        return None
    if not data['objects']:
        return None
    return data


def _write_cache(data):
    temp_file = CACHE_FILE + '.tmp'
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(temp_file, CACHE_FILE)
    except Exception:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except OSError:
            pass


def _download_bundle():
    try:
        session = create_session()
        response = session.get(ATTACK_URL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        _report_error("Error downloading ATT&CK matrix: %s" % e)
        return None


def _load_bundle():
    global _bundle, _bundle_failed
    if _bundle is not None:
        return _bundle
    if _bundle_failed:
        return {}, {}, {}
    data = _read_cache()
    if data is None:
        data = _download_bundle()
        if data is not None:
            _write_cache(data)
    if data is None:
        _bundle_failed = True
        return {}, {}, {}
    try:
        parsed = _parse_bundle(data)
    except Exception as e:
        _report_error("Error parsing ATT&CK matrix: %s" % e)
        _bundle_failed = True
        return {}, {}, {}
    if not parsed[0]:
        _report_error("ATT&CK matrix contains no technique, mapping unavailable.")
        _bundle_failed = True
        return {}, {}, {}
    _bundle = parsed
    return _bundle


class AttackMapper:
    def __init__(self, autoload=False):
        self.techniques = {}
        self.name_index = {}
        self.alias_index = {}
        if autoload:
            self.load()

    def load(self):
        if not self.techniques:
            self.techniques, self.name_index, self.alias_index = _load_bundle()
        return bool(self.techniques)

    def _load_techniques(self, data):
        self.techniques, self.name_index, self.alias_index = _parse_bundle(data)

    def _match_by_id(self, tag):
        hits = []
        for token in _ID_TOKEN_RE.findall(tag):
            technique_id = token.upper()
            if technique_id not in self.techniques and '.' in technique_id:
                technique_id = technique_id.split('.')[0]
            if technique_id in self.techniques:
                hits.append((MATCH_BY_ID, technique_id))
        return hits

    def _match_by_fuzzy(self, squashed):
        if len(squashed) < FUZZY_MIN_LENGTH:
            return []
        tolerance = max(2, len(squashed) // 4)
        matcher = SequenceMatcher(None, '', squashed)
        scored = []
        for key, technique_ids in self.name_index.items():
            if abs(len(key) - len(squashed)) > tolerance:
                continue
            matcher.set_seq1(key)
            if matcher.real_quick_ratio() < FUZZY_MIN_RATIO:
                continue
            if matcher.quick_ratio() < FUZZY_MIN_RATIO:
                continue
            ratio = matcher.ratio()
            if ratio < FUZZY_MIN_RATIO:
                continue
            for technique_id in technique_ids:
                scored.append((ratio, technique_id))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [(MATCH_BY_FUZZY, technique_id) for _, technique_id in scored]

    def match_tag(self, tag, fuzzy=False):
        if not isinstance(tag, str):
            tag = str(tag)
        tag = tag.strip()
        if not tag:
            return []
        hits = self._match_by_id(tag)
        if hits:
            return hits
        squashed = _squash(tag)
        if len(squashed) < MIN_TAG_LENGTH:
            return []
        for technique_id in self.name_index.get(squashed, []):
            hits.append((MATCH_BY_NAME, technique_id))
        if hits:
            return hits
        for technique_id in self.alias_index.get(squashed, []):
            hits.append((MATCH_BY_ALIAS, technique_id))
        if hits or not fuzzy:
            return hits
        return self._match_by_fuzzy(squashed)

    def map_tags(self, tags, fuzzy=False, max_results=MAX_MATCHES_TOTAL,
                 per_tag_limit=MAX_MATCHES_PER_TAG, collapse_parents=True):
        if not self.load():
            return []
        best = {}
        for tag in (tags or []):
            hits = self.match_tag(tag, fuzzy=fuzzy)
            if per_tag_limit and per_tag_limit > 0:
                hits = hits[:per_tag_limit]
            for tier, technique_id in hits:
                previous = best.get(technique_id)
                if previous is None or tier < previous[0]:
                    best[technique_id] = (tier, str(tag).strip())
        if collapse_parents:
            for technique_id in list(best):
                if '.' not in technique_id:
                    continue
                parent = technique_id.split('.')[0]
                if parent in best:
                    del best[parent]
        ordered = sorted(best.items(), key=lambda item: (item[1][0], item[0]))
        if max_results and max_results > 0:
            ordered = ordered[:max_results]
        matched = []
        for technique_id, (tier, tag) in ordered:
            info = self.techniques.get(technique_id)
            if not info:
                continue
            entry = {'id': technique_id}
            entry.update(info)
            entry['matched_tag'] = tag
            entry['match_type'] = _MATCH_LABELS.get(tier, 'unknown')
            if '.' in technique_id:
                entry['parent_id'] = technique_id.split('.')[0]
            matched.append(entry)
        return matched

    def format_techniques(self, techniques, label=None):
        if is_text_output():
            for tech in techniques:
                tactics = ', '.join(tech.get('kill_chain_phases', []))
                technique_id = tech['id'].ljust(ID_COLUMN_WIDTH)
                name = _shorten(tech['name'], NAME_COLUMN_WIDTH).ljust(NAME_COLUMN_WIDTH)
                if cv.bkg == 1:
                    print(
                        f"{mycolors.foreground.lightcyan}"
                        f"{technique_id}"
                        f"{mycolors.foreground.yellow}"
                        f"{name}"
                        f"{mycolors.foreground.lightgreen}"
                        f"{tactics}"
                        f"{mycolors.reset}"
                    )
                else:
                    print(
                        f"{mycolors.foreground.blue}"
                        f"{technique_id}"
                        f"{mycolors.foreground.blue}"
                        f"{name}"
                        f"{mycolors.foreground.blue}"
                        f"{tactics}"
                        f"{mycolors.reset}"
                    )
        for tech in techniques:
            record = {
                'technique_id': tech['id'],
                'name': tech['name'],
                'tactics': tech.get('kill_chain_phases', []),
                'url': tech.get('url', ''),
            }
            if label:
                record['source'] = str(label)
            collector.add(record)


def get_mapper():
    global _mapper
    if _mapper is None:
        _mapper = AttackMapper()
    if not _mapper.load():
        return None
    return _mapper


def map_and_display(values, label=None, fuzzy=False,
                    max_results=MAX_MATCHES_TOTAL, header=True):
    if not cv.attack_map:
        return []
    try:
        if not values:
            return []
        mapper = get_mapper()
        if mapper is None:
            return []
        techniques = mapper.map_tags(values, fuzzy=fuzzy, max_results=max_results)
        if not techniques:
            return []
        if header and is_text_output():
            title = "MITRE ATT&CK Mapping"
            if label:
                title = title + " (" + str(label) + ")"
            print(mycolors.foreground.error(cv.bkg) + "\n\n" + title + ":" + mycolors.reset)
        mapper.format_techniques(techniques, label=label)
        return techniques
    except Exception:
        return []
