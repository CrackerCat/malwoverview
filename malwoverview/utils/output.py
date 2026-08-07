import sys
import json
import csv
import io
import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors

_CSV_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t')


def csv_safe(value):
    if isinstance(value, (list, tuple)):
        value = ', '.join(str(item) for item in value)
    text = str(value).replace('\r', ' ').replace('\n', ' ')
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


def flat_record(service, query_type, item, **extra):
    record = {'service': service, 'query_type': query_type}
    record.update(extra)
    if isinstance(item, dict):
        for key, value in item.items():
            if value is None or isinstance(value, (str, int, float, bool)):
                record[key] = value
            elif isinstance(value, (list, tuple)):
                flat = [str(v) for v in value if isinstance(v, (str, int, float, bool))]
                if flat:
                    record[key] = ', '.join(flat)
    return record


_NO_RESULT_KEYS = {'message', 'error', 'errors', 'detail', 'reason'}
_OK_STATUS = ('ok', 'success', 'found')


def _is_no_result(item):
    status = item.get('query_status')
    if isinstance(status, str) and status.strip().lower() not in _OK_STATUS:
        return True
    keys = set(item)
    return bool(keys) and keys <= _NO_RESULT_KEYS


def _keyed(mapping):
    return [{'key': key, **value} if isinstance(value, dict) else {'key': key, 'value': value}
            for key, value in mapping.items()]


def add_records(service, query_type, parsed, **extra):
    if isinstance(parsed, dict):
        inner = parsed.get('data')
        if isinstance(inner, list):
            items = inner
        elif isinstance(inner, dict) and inner:
            attributes = inner.get('attributes')
            if isinstance(attributes, dict):
                outer = {k: v for k, v in inner.items() if k != 'attributes'}
                items = [{**outer, **attributes}]
            elif all(isinstance(v, dict) for v in inner.values()):
                items = _keyed(inner)
            else:
                items = [inner]
        elif parsed and all(isinstance(v, dict) for v in parsed.values()):
            items = _keyed(parsed)
        else:
            items = [parsed]
    elif isinstance(parsed, list):
        items = parsed
    else:
        return 0

    added = 0
    for item in items:
        if isinstance(item, dict) and item:
            if _is_no_result(item):
                continue
            collector.add(flat_record(service, query_type, item, **extra))
            added += 1
        elif isinstance(item, (str, int, float)) and item != '':
            record = {'service': service, 'query_type': query_type}
            record.update(extra)
            record['value'] = item
            collector.add(record)
            added += 1
    return added


class ResultCollector:
    def __init__(self):
        self.records = []
        self._current = {}

    def add(self, record):
        if isinstance(record, dict):
            self.records.append(record)
        elif isinstance(record, list):
            self.records.extend(record)

    def start_record(self):
        self._current = {}

    def field(self, key, value):
        self._current[key] = value

    def end_record(self):
        if self._current:
            self.records.append(self._current)
            self._current = {}

    def finalize(self, file=None):
        if cv.output_format not in ('json', 'csv'):
            return

        if file is None:
            file = sys.stdout
            try:
                file.reconfigure(encoding='utf-8', errors='replace', newline='')
            except (AttributeError, ValueError):
                pass

        if cv.output_format == 'json':
            json.dump(self.records, file, indent=2, default=str)
            print(file=file)
        elif cv.output_format == 'csv':
            if not self.records:
                return
            all_keys = []
            seen = set()
            for record in self.records:
                for key in record:
                    if key not in seen:
                        all_keys.append(key)
                        seen.add(key)
            writer = csv.DictWriter(file, fieldnames=all_keys, extrasaction='ignore')
            writer.writerow({key: csv_safe(key) for key in all_keys})
            for record in self.records:
                writer.writerow({k: csv_safe(v) for k, v in record.items()})

    def clear(self):
        self.records = []
        self._current = {}


collector = ResultCollector()


def is_text_output():
    return cv.output_format == 'text'
