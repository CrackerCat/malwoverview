import os
import warnings

from malwoverview.utils.colors import mycolors, printr, strip_terminal_escapes, strip_json_escapes, bullet, pad, fit, column
import malwoverview.modules.configvars as cv
from malwoverview.utils.output import collector, is_text_output

COL_STRINGS = 9
COL_TAGS_MAX = 28
COL_DESC_MAX = 50
COL_GUTTER = 2
TABLE_MIN_WIDTH = 100


class YaraScanner:
    RULE_EXTENSIONS = ('.yar', '.yara')

    def __init__(self, rules_path):
        self.rules_path = os.path.abspath(rules_path)
        self.available = False
        self.rules = None
        self.skipped = []
        self.rule_files = []
        self._compiled_count = 0

        if not os.path.exists(self.rules_path):
            print(
                f"{mycolors.foreground.error(cv.bkg)}"
                f"YARA rules path not found: {self.rules_path}"
                f"{mycolors.reset}"
            )
            return

        try:
            import yara
        except ImportError:
            print(
                f"{mycolors.foreground.warning(cv.bkg)}"
                "YARA scanning requires yara-python: "
                "pip install malwoverview[yara]"
                f"{mycolors.reset}"
            )
            return

        self._yara = yara

        if os.path.isdir(self.rules_path):
            self.rule_files = self._collect_rule_files(self.rules_path)
            if not self.rule_files:
                print(
                    f"{mycolors.foreground.error(cv.bkg)}"
                    f"No {' or '.join(YaraScanner.RULE_EXTENSIONS)} files found under: "
                    f"{self.rules_path}"
                    f"{mycolors.reset}"
                )
                return
            self.rules, self.skipped = self._compile_many(self.rule_files)
        else:
            self.rule_files = [self.rules_path]
            try:
                self.rules = yara.compile(filepath=self.rules_path)
                self._compiled_count = 1
            except (yara.SyntaxError, yara.Error):
                includes = self._parse_includes(self.rules_path)
                targets = includes if includes else [self.rules_path]
                self.rules, self.skipped = self._compile_many(targets)

        if self.rules:
            self.available = True
        else:
            print(
                f"{mycolors.foreground.error(cv.bkg)}"
                "All YARA rules failed to compile. Check your rules."
                f"{mycolors.reset}"
            )

    @staticmethod
    def _collect_rule_files(dirpath):
        found = []
        for root, dirs, files in os.walk(dirpath):
            dirs.sort()
            for fname in sorted(files):
                if fname.lower().endswith(YaraScanner.RULE_EXTENSIONS):
                    found.append(os.path.join(root, fname))
        return found

    def _namespaces(self, paths):
        if os.path.isdir(self.rules_path):
            base = self.rules_path
        else:
            base = os.path.dirname(self.rules_path)
        namespaces = {}
        for path in paths:
            try:
                name = os.path.relpath(path, base).replace(os.sep, '/')
            except ValueError:
                name = os.path.basename(path)
            if name in namespaces:
                name = f"{name}#{len(namespaces)}"
            namespaces[name] = path
        return namespaces

    @staticmethod
    def _parse_includes(rules_path):
        rules_dir = os.path.dirname(rules_path)
        includes = []
        try:
            with open(rules_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('include') and '"' in line:
                        inc_path = line.split('"')[1]
                        full_path = os.path.normpath(os.path.join(rules_dir, inc_path))
                        if os.path.isfile(full_path):
                            includes.append(full_path)
        except Exception:
            return []
        return includes

    def _compile_many(self, paths):
        yara = self._yara
        namespaces = self._namespaces(paths)

        try:
            rules = yara.compile(filepaths=namespaces)
            self._compiled_count = len(namespaces)
            return rules, []
        except (yara.SyntaxError, yara.Error):
            pass

        valid = {}
        skipped = []
        for name, path in namespaces.items():
            try:
                yara.compile(filepath=path)
                valid[name] = path
            except (yara.SyntaxError, yara.Error) as e:
                skipped.append((os.path.basename(path), str(e)))
            except Exception:
                skipped.append((os.path.basename(path), 'unknown error'))

        if skipped and cv.verbosity >= 1:
            self._report_skipped(skipped)

        if not valid:
            return None, skipped

        try:
            rules = yara.compile(filepaths=valid)
        except (yara.SyntaxError, yara.Error):
            return None, skipped

        self._compiled_count = len(valid)
        return rules, skipped

    @staticmethod
    def _report_skipped(skipped):
        print(
            f"{mycolors.foreground.warning(cv.bkg)}"
            f"Skipped {len(skipped)} rule file(s) with syntax errors:"
            f"{mycolors.reset}"
        )
        for name, err in skipped[:10]:
            msg = str(err).split('\n')[0]
            base = os.path.basename(name)
            marker = msg.find(base)
            if marker > 0:
                msg = msg[marker + len(base):].lstrip()
            print(f"  {name}: {msg[:160]}")
        if len(skipped) > 10:
            print(f"  ... and {len(skipped) - 10} more")
        print()

    def scan_file(self, filepath):
        if not self.available:
            return []
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                matches = self.rules.match(filepath)
        except Exception:
            return []
        results = []
        for match in matches:
            results.append({
                'rule': strip_terminal_escapes(str(match.rule)),
                'namespace': strip_terminal_escapes(str(match.namespace)),
                'tags': [strip_terminal_escapes(str(t)) for t in match.tags],
                'meta': strip_json_escapes(match.meta),
                'strings_count': len(match.strings),
            })
        return results

    def scan_directory(self, dirpath):
        results = []
        for root, _dirs, files in os.walk(dirpath):
            for fname in files:
                fpath = os.path.join(root, fname)
                file_results = self.scan_file(fpath)
                for r in file_results:
                    r['file'] = fpath
                results.extend(file_results)
        return results

    @staticmethod
    def _cells(r):
        return (
            strip_terminal_escapes(os.path.basename(r.get('file', ''))),
            r['rule'],
            ', '.join(r['tags']) if r['tags'] else '',
            str(r['strings_count']),
            str(r.get('meta', {}).get('description', '')),
        )

    def _widths(self, results):
        rows = [self._cells(r) for r in results]
        widths = {
            'file': column("File", [c[0] for c in rows], gutter=COL_GUTTER),
            'rule': column("Rule", [c[1] for c in rows], gutter=COL_GUTTER),
            'tags': column("Tags", [c[2] for c in rows], cap=COL_TAGS_MAX, gutter=COL_GUTTER),
            'desc': column("Description", [c[4] for c in rows], cap=COL_DESC_MAX, gutter=0),
        }
        widths['total'] = (widths['file'] + widths['rule'] + widths['tags']
                           + COL_STRINGS + widths['desc'])
        return widths

    def _print_header(self, width):
        print()
        print(mycolors.reset + "YARA SCAN REPORT".center(width))
        print(mycolors.foreground.neutral(cv.bkg) + (width * '-') + mycolors.reset)

    def _print_summary(self, matches, width, files_matched=None):
        structure = mycolors.foreground.neutral(cv.bkg)
        print()
        if self._compiled_count > 1 or self.skipped:
            print(bullet("Rule files: %d | Compiled: %d | Skipped: %d"
                         % (len(self.rule_files), self._compiled_count, len(self.skipped)),
                         width, structure))
            if self.skipped and cv.verbosity < 1:
                print(bullet("A skipped rule file did not compile against this version of YARA. "
                             "Run the same command with --verbose to see which files and why.",
                             width, structure))
        if files_matched is None:
            print(bullet("Matches found: %d" % matches, width, structure))
        else:
            print(bullet("Matches found: %d across %d file(s)" % (matches, files_matched),
                         width, structure))

    def _print_table_header(self, widths):
        structure = mycolors.foreground.neutral(cv.bkg)
        print(
            structure
            + "File".ljust(widths['file'])
            + "Rule".ljust(widths['rule'])
            + "Tags".ljust(widths['tags'])
            + "Strings".ljust(COL_STRINGS)
            + "Description"
            + mycolors.reset
        )
        print(structure + (widths['total'] * '-') + mycolors.reset)

    def _print_table_row(self, r, widths):
        fname, rule, tags, strings, desc = self._cells(r)

        print(
            mycolors.foreground.info(cv.bkg) + pad(fname, widths['file'])
            + mycolors.foreground.error(cv.bkg) + pad(rule, widths['rule'])
            + mycolors.foreground.accent(cv.bkg) + pad(fit(tags, widths['tags'] - COL_GUTTER), widths['tags'])
            + mycolors.foreground.ok(cv.bkg) + pad(strings, COL_STRINGS)
            + mycolors.foreground.neutral(cv.bkg) + fit(desc, widths['desc'])
            + mycolors.reset
        )

    def _display_single_file(self, results):
        if not results:
            print(bullet("No YARA matches found.", TABLE_MIN_WIDTH))
            return

        COLSIZE = 20
        for r in results:
            fields = {
                'Rule': r['rule'],
            }
            fields['Tags'] = ', '.join(r['tags']) if r['tags'] else 'none'
            fields['Strings matched'] = str(r['strings_count'])
            if r.get('meta'):
                for k, v in r['meta'].items():
                    fields[f'  {k}'] = str(v)

            for field, value in fields.items():
                print(
                    mycolors.foreground.info(cv.bkg)
                    + f"{field}:".ljust(COLSIZE) + "\t"
                    + mycolors.reset + value
                )
            print()

        self._print_summary(len(results), TABLE_MIN_WIDTH)

    def _display_directory(self, results):
        if not results:
            print(bullet("No YARA matches found.", TABLE_MIN_WIDTH))
            return

        files_scanned = set()
        for r in results:
            if r.get('file'):
                files_scanned.add(r['file'])

        widths = self._widths(results)
        self._print_table_header(widths)
        for r in results:
            self._print_table_row(r, widths)

        self._print_summary(len(results), widths['total'], len(files_scanned))

    def scan_and_display(self, target):
        target = os.path.abspath(target)
        is_dir = os.path.isdir(target)

        if is_dir:
            results = self.scan_directory(target)
        else:
            results = self.scan_file(target)

        if is_text_output():
            if is_dir and results:
                self._print_header(self._widths(results)['total'])
                self._display_directory(results)
            else:
                self._print_header(TABLE_MIN_WIDTH)
                if is_dir:
                    self._display_directory(results)
                else:
                    self._display_single_file(results)

        collector.add(results)
        printr()
