import os
import re
import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import (
    mycolors, printr, strip_terminal_escapes, bullet, display_width, pad, fit,
    column as _column,
)
from malwoverview.utils.output import collector, is_text_output
from malwoverview.utils.peinfo import ftype, isoverlay, overlaysize, humansize, fileentropy
from malwoverview.utils.authenticode import (
    signature_info, signify_available, unavailable_notice, certificate_expired,
    is_weak_digest, SIG_VALID, SIG_NONE, SIG_NOTPE, SIG_PRESENT, SIG_BAD_STATUSES,
    VERIFY_MODES, DEFAULT_VERIFY_MODE,
)


COL_SIZE = 11
COL_OVERLAY = 9
COL_OVLSIZE = 11
COL_ENTROPY = 6
COL_SIGNED = 11
COL_EXPIRES = 19
COL_GUTTER = 2
COL_SIGNER_MAX = 60
COL_TYPE_MAX = len("PE32 executable (GUI) Intel 80386 Mono/.Net assembly,")

PE_MAGIC_RE = re.compile(r'^PE[0-9]{2}|^MS-DOS')
MAX_DETAIL_LENGTH = 200
HIGH_ENTROPY = 7.0
MAX_ENTROPY = 8.0


def _clean(value):
    return strip_terminal_escapes(str(value)) if value else value


def column(header, values, cap=None):
    return _column(header, values, cap=cap, gutter=COL_GUTTER)


def truncate(value, maxlen):
    text = str(value)
    if display_width(text) <= maxlen:
        return text
    if maxlen < 4:
        return fit(text, maxlen, marker='')
    return fit(text, maxlen)


class PEScanner:
    def __init__(self, threshold=HIGH_ENTROPY, check_signature=True, verify_mode=DEFAULT_VERIFY_MODE):
        try:
            self.threshold = float(threshold)
        except (TypeError, ValueError):
            self.threshold = HIGH_ENTROPY
        self.check_signature = bool(check_signature)
        self.verify_mode = verify_mode if verify_mode in VERIFY_MODES else DEFAULT_VERIFY_MODE

    def _collect_targets(self, target):
        if os.path.isfile(target):
            return [target]

        targets = []
        for root, _dirs, files in os.walk(target):
            for name in sorted(files):
                targets.append(os.path.join(root, name))
        return targets

    def _analyze(self, path):
        record = {
            'service': 'peinfo',
            'query_type': 'pe_scan',
            'filename': strip_terminal_escapes(os.path.basename(path)),
            'path': path,
            'filetype': 'unknown',
            'size_bytes': 0,
            'is_pe': False,
            'overlay': 'N/A',
            'overlay_size_bytes': 0,
            'entropy': 0.0,
            'signature_status': SIG_NOTPE,
            'signer': '',
            'signature_issuer': '',
            'signature_valid_from': '',
            'signature_valid_to': '',
            'signature_timestamp': '',
            'signature_algorithm': '',
            'signature_thumbprint': '',
            'signature_serial': '',
            'signature_count': 0,
            'signature_primary_index': 0,
            'signature_signers': [],
            'signature_algorithms': [],
            'signature_thumbprints': [],
            'signature_detail': '',
        }

        try:
            record['size_bytes'] = os.path.getsize(path)
        except OSError:
            pass

        try:
            record['filetype'] = strip_terminal_escapes(str(ftype(path)))
        except Exception:
            pass

        record['is_pe'] = bool(PE_MAGIC_RE.search(str(record['filetype'])))

        if record['is_pe']:
            try:
                record['overlay'] = isoverlay(path)
            except Exception:
                record['overlay'] = 'N/A'
            if record['overlay'] == 'YES':
                try:
                    record['overlay_size_bytes'] = overlaysize(path)
                except Exception:
                    record['overlay_size_bytes'] = 0

        try:
            record['entropy'] = round(fileentropy(path), 2)
        except Exception:
            record['entropy'] = 0.0

        entries = []

        if record['is_pe']:
            signature = signature_info(path, verify=self.check_signature,
                                       verify_mode=self.verify_mode)
            record['signature_status'] = signature['status']
            record['signer'] = _clean(signature['signer'])
            record['signature_issuer'] = _clean(signature['issuer'])
            record['signature_valid_from'] = _clean(signature['valid_from'])
            record['signature_valid_to'] = _clean(signature['valid_to'])
            record['signature_timestamp'] = _clean(signature['timestamp'])
            record['signature_algorithm'] = _clean(signature.get('algorithm', ''))
            record['signature_thumbprint'] = _clean(signature.get('thumbprint', ''))
            record['signature_serial'] = _clean(signature.get('serial_number', ''))
            record['signature_count'] = signature.get('count', 0)
            record['signature_primary_index'] = signature.get('primary_index', 0)
            record['signature_detail'] = _clean(signature['detail'])

            entries = [{k: _clean(v) for k, v in e.items()}
                       for e in (signature.get('signatures') or [])]
            record['signature_signers'] = [e['signer'] for e in entries]
            record['signature_algorithms'] = [e['algorithm'] for e in entries]
            record['signature_thumbprints'] = [e['thumbprint'] for e in entries]

        return record, entries

    def _scan_widths(self, records):
        name = column("Filename", [r['filename'] for r in records])
        filetype = column("Type", [r['filetype'] for r in records], cap=COL_TYPE_MAX)
        return {
            'name': name,
            'type': filetype,
            'total': name + filetype + COL_SIZE + COL_OVERLAY + COL_OVLSIZE + COL_ENTROPY + COL_SIGNED,
        }

    def _print_header(self, target, total, widths):
        structure = mycolors.foreground.neutral(cv.bkg)
        print("\n")
        print((mycolors.reset + "LOCAL PE TRIAGE".center(widths['total'])), end='')
        print("\n" + structure + (widths['total'] * '-') + mycolors.reset)
        print(mycolors.foreground.info(cv.bkg) + "Target: ".ljust(12) + mycolors.reset + str(target))
        print(mycolors.foreground.info(cv.bkg) + "Files: ".ljust(12) + mycolors.reset + str(total))
        print()
        print(
            structure
            + "Filename".ljust(widths['name'])
            + "Type".ljust(widths['type'])
            + "Size".ljust(COL_SIZE)
            + "Overlay".center(COL_OVERLAY)
            + "Ovl Size".ljust(COL_OVLSIZE)
            + "Ent".ljust(COL_ENTROPY)
            + "Signed"
            + mycolors.reset
        )
        print(structure + (widths['total'] * '-') + mycolors.reset)

    def _print_row(self, record, widths):
        if record['entropy'] >= self.threshold:
            entcolor = mycolors.foreground.error(cv.bkg)
        else:
            entcolor = mycolors.foreground.success(cv.bkg)

        ovlsize = humansize(record['overlay_size_bytes']) if record['overlay'] == 'YES' else '-'

        print(
            mycolors.foreground.success(cv.bkg)
            + pad(record['filename'], widths['name'])
            + mycolors.reset
            + pad(truncate(record['filetype'], widths['type'] - COL_GUTTER), widths['type'])
            + mycolors.foreground.info(cv.bkg)
            + humansize(record['size_bytes']).ljust(COL_SIZE)
            + mycolors.reset
            + record['overlay'].center(COL_OVERLAY)
            + mycolors.foreground.info(cv.bkg)
            + ovlsize.ljust(COL_OVLSIZE)
            + entcolor
            + ("%.2f" % record['entropy']).ljust(COL_ENTROPY)
            + self._status_color(record['signature_status'])
            + record['signature_status']
            + mycolors.reset
        )

    def _signer_label(self, record):
        extra = record['signature_count'] - 1
        suffix = ' (+%d)' % extra if extra > 0 else ''
        return (record['signer'] or '-') + suffix

    @staticmethod
    def _fit_signer(label, maxlen):
        if display_width(label) <= maxlen:
            return label
        suffix = ''
        if label.endswith(')') and ' (+' in label:
            head, _, tail = label.rpartition(' (+')
            suffix = ' (+' + tail
            label = head
        return truncate(label, max(4, maxlen - display_width(suffix))) + suffix

    def _status_color(self, status):
        if status in SIG_BAD_STATUSES:
            return mycolors.foreground.error(cv.bkg)
        if status == SIG_VALID:
            return mycolors.foreground.success(cv.bkg)
        return mycolors.foreground.neutral(cv.bkg)

    def _entry_fields(self, entry):
        accent = mycolors.foreground.accent(cv.bkg)
        pivot = mycolors.foreground.success(cv.bkg)

        fields = []
        if entry['algorithm']:
            weak = is_weak_digest(entry['algorithm'])
            label = entry['algorithm'] + ('   (deprecated for Authenticode since 2016)' if weak else '')
            fields.append(('Digest', label,
                           mycolors.foreground.warning(cv.bkg) if weak else mycolors.foreground.info(cv.bkg)))
        if entry['signer']:
            fields.append(('Signer', entry['signer'], accent))
        if entry['issuer']:
            fields.append(('Issuer', entry['issuer'], accent))
        if entry['valid_from']:
            expired = certificate_expired(entry['valid_to'])
            fields.append(('Certificate', entry['valid_from'] + '  ->  ' + entry['valid_to'],
                           mycolors.foreground.error(cv.bkg) if expired else mycolors.reset))
        if entry['thumbprint']:
            fields.append(('Thumbprint', entry['thumbprint'], pivot))
        if entry['serial_number']:
            fields.append(('Serial', entry['serial_number'], pivot))
        if entry['timestamp']:
            fields.append(('Timestamped', entry['timestamp'], mycolors.reset))
        return fields

    def _print_fields(self, fields, status=None):
        if not fields:
            return
        colsize = max(len(f[0]) for f in fields) + 3
        for field in fields:
            name, value = field[0], field[1]
            if name == 'Signature' and status is not None:
                valuecolor = self._status_color(status)
            elif len(field) > 2:
                valuecolor = field[2]
            else:
                valuecolor = mycolors.reset
            print(mycolors.foreground.neutral(cv.bkg) + (name + ':').ljust(colsize)
                  + valuecolor + str(value) + mycolors.reset)

    def _print_signature_detail(self, record, entries):
        if record['signature_status'] in (SIG_NOTPE,):
            return

        print()
        fields = [('Signature', record['signature_status'])]
        if record['signature_count'] > 1:
            fields.append(('Embedded', '%d signatures' % record['signature_count']))
        if len(entries) == 1:
            fields.extend(self._entry_fields(entries[0]))
        elif not entries:
            if record['signer']:
                fields.append(('Signer', record['signer']))
            if record['signature_issuer']:
                fields.append(('Issuer', record['signature_issuer']))
            if record['signature_valid_from']:
                fields.append(('Certificate', record['signature_valid_from'] + '  ->  ' + record['signature_valid_to']))
            if record['signature_timestamp']:
                fields.append(('Timestamped', record['signature_timestamp']))
        if record['signature_detail']:
            fields.append(('Detail', truncate(record['signature_detail'], MAX_DETAIL_LENGTH)))

        self._print_fields(fields, record['signature_status'])

        if len(entries) > 1:
            for index, entry in enumerate(entries):
                print()
                primary = index == record.get('signature_primary_index', 0)
                label = "Signature %d of %d" % (index + 1, len(entries))
                print(mycolors.bold + mycolors.foreground.accent(cv.bkg) + label + mycolors.reset, end='')
                if primary:
                    print(mycolors.foreground.success(cv.bkg)
                          + "  (verdict above was decided by this one: --sig-verify-mode %s)" % self.verify_mode
                          + mycolors.reset, end='')
                print()
                self._print_fields(self._entry_fields(entry))

    def scan_and_display(self, target):
        if not target or not os.path.exists(target):
            print(mycolors.foreground.error(cv.bkg) + "\nThe file or directory was not found: %s\n" % target + mycolors.reset)
            printr()
            return False

        targets = self._collect_targets(target)

        if not targets:
            print(mycolors.foreground.error(cv.bkg) + "\nNo files were found in: %s\n" % target + mycolors.reset)
            printr()
            return False

        if is_text_output() and len(targets) > 1:
            print(mycolors.foreground.neutral(cv.bkg)
                  + "\nAnalyzing %d file(s)..." % len(targets) + mycolors.reset, flush=True)

        pecount = 0
        highcount = 0
        overlaycount = 0
        records = []
        lastentries = []

        for path in targets:
            record, lastentries = self._analyze(path)
            collector.add(record)
            records.append(record)

            if record['is_pe']:
                pecount += 1
            if record['entropy'] >= self.threshold:
                highcount += 1
            if record['overlay'] == 'YES':
                overlaycount += 1

        if is_text_output():
            widths = self._scan_widths(records)
            self._print_header(target, len(targets), widths)
            for record in records:
                self._print_row(record, widths)
            total = widths['total']
            print(mycolors.foreground.neutral(cv.bkg) + (total * '-') + mycolors.reset)
            print()
            print(bullet("%d file(s): %d PE, %d non-PE. %d with an overlay. %d with entropy >= %.2f (max %.1f)."
                         % (len(targets), pecount, len(targets) - pecount, overlaycount,
                            highcount, self.threshold, MAX_ENTROPY), total))
            self._print_signature_summary(records, pecount, total)
            print(bullet("Entropy is the highest PE section entropy, or the whole-file Shannon entropy for non-PE files.", total))
            print(bullet("Overlay bytes sit outside every section, so a small stub carrying a large packed overlay keeps a low entropy value: read the Overlay columns beside it.", total))
            if any(r['overlay'] == 'YES' and r['signature_status'] not in (SIG_NONE, SIG_NOTPE) for r in records):
                print(bullet("An embedded signature is itself stored in the overlay, so a signed file always reports one: that overlay is not an appended payload.", total))
            print(bullet("Only embedded signatures are checked. A file reported as NONE can still be signed through a Windows catalog file.", total))
            print()
            if len(records) == 1:
                self._print_signature_detail(records[0], lastentries)
                print()

        printr()
        return True

    def signature_and_display(self, target):
        if not target or not os.path.exists(target):
            print(mycolors.foreground.error(cv.bkg) + "\nThe file or directory was not found: %s\n" % target + mycolors.reset)
            printr()
            return False

        targets = self._collect_targets(target)

        if not targets:
            print(mycolors.foreground.error(cv.bkg) + "\nNo files were found in: %s\n" % target + mycolors.reset)
            printr()
            return False

        if is_text_output() and len(targets) > 1:
            print(mycolors.foreground.neutral(cv.bkg)
                  + "\nAnalyzing %d file(s)..." % len(targets) + mycolors.reset, flush=True)

        records = []
        pecount = 0
        lastentries = []

        for path in targets:
            record, lastentries = self._analyze(path)
            collector.add(record)
            records.append(record)
            if record['is_pe']:
                pecount += 1

        if is_text_output():
            signers = [self._signer_label(r) for r in records]
            namewidth = column("Filename", [r['filename'] for r in records])
            signerwidth = column("Signer", signers, cap=COL_SIGNER_MAX)
            signers = [self._fit_signer(s, signerwidth - COL_GUTTER) for s in signers]
            total = namewidth + COL_SIGNED + signerwidth + COL_EXPIRES

            structure = mycolors.foreground.neutral(cv.bkg)

            print("\n")
            print((mycolors.bold + mycolors.foreground.accent(cv.bkg)
                   + "DIGITAL SIGNATURE CHECK".center(total) + mycolors.reset), end='')
            print("\n" + structure + (total * '-') + mycolors.reset)
            print(mycolors.foreground.info(cv.bkg) + "Target: ".ljust(12) + mycolors.reset + str(target))
            print(mycolors.foreground.info(cv.bkg) + "Files: ".ljust(12) + mycolors.reset + str(len(targets)))
            print()
            print(
                structure
                + "Filename".ljust(namewidth)
                + "Status".ljust(COL_SIGNED)
                + "Signer".ljust(signerwidth)
                + "Certificate Expires"
                + mycolors.reset
            )
            print(structure + (total * '-') + mycolors.reset)

            for record, signer in zip(records, signers):
                expires = record['signature_valid_to'][:10] or '-'
                if certificate_expired(record['signature_valid_to']):
                    expirycolor = mycolors.foreground.error(cv.bkg)
                elif expires == '-':
                    expirycolor = mycolors.foreground.info(cv.bkg)
                else:
                    expirycolor = mycolors.foreground.success(cv.bkg)

                print(
                    mycolors.foreground.info(cv.bkg)
                    + pad(record['filename'], namewidth)
                    + self._status_color(record['signature_status'])
                    + record['signature_status'].ljust(COL_SIGNED)
                    + mycolors.foreground.accent(cv.bkg)
                    + pad(signer, signerwidth)
                    + expirycolor
                    + expires
                    + mycolors.reset
                )

            print(structure + (total * '-') + mycolors.reset)
            print()
            print(bullet("%d file(s): %d PE, %d non-PE."
                         % (len(targets), pecount, len(targets) - pecount), total))
            self._print_signature_summary(records, pecount, total)
            print(bullet("Only embedded signatures are checked. A file reported as NONE can still be signed through a Windows catalog file.", total))
            print()
            if len(records) == 1:
                self._print_signature_detail(records[0], lastentries)
                print()

        printr()
        return True

    def _print_signature_summary(self, records, pecount, width):
        if not pecount:
            return

        if not self.check_signature:
            print(bullet("Signature verification was skipped (--no-signature).", width))
            return

        if not signify_available():
            print(bullet(unavailable_notice(), width))

        counts = {}
        for record in records:
            status = record['signature_status']
            if status == SIG_NOTPE:
                continue
            counts[status] = counts.get(status, 0) + 1

        if not counts:
            return

        bad = sum(counts.get(status, 0) for status in SIG_BAD_STATUSES)
        parts = ", ".join("%d %s" % (counts[status], status) for status in sorted(counts))
        color = mycolors.foreground.error(cv.bkg) if bad else None
        print(bullet("Signatures: " + parts + ".", width, color))

        if counts.get(SIG_VALID):
            print(bullet("VALID means the file still matches the certificate it was signed with. It is not a verdict on the file: "
                         "signing certificates are stolen, abused and issued by mistake, and malware has carried valid Microsoft signatures.", width))
            print(bullet("Revocation is not checked either: no network request is made, so a file signed with a certificate that was revoked afterwards still reports VALID.", width))

        multi = [r for r in records if r['signature_count'] > 1]
        if multi:
            print(bullet("%d file(s) carry more than one embedded signature, and the signers often differ. The status of each one was decided by --sig-verify-mode %s; "
                         "run --sigcheck on a single file to list every signer." % (len(multi), self.verify_mode), width))

        countersigned = [r for r in records
                         if r['signature_status'] == SIG_VALID
                         and r['signature_timestamp']
                         and certificate_expired(r['signature_valid_to'])]
        if countersigned:
            print(bullet("%d of them stayed VALID with an expired certificate: the countersignature proves the file was signed while the certificate was still valid, which is how Authenticode is meant to work."
                         % len(countersigned), width))
