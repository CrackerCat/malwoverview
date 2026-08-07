import os
import pefile

from malwoverview.utils.colors import strip_terminal_escapes

SIG_VALID = 'VALID'
SIG_TAMPERED = 'TAMPERED'
SIG_UNTRUSTED = 'UNTRUSTED'
SIG_EXPIRED = 'EXPIRED'
SIG_MALFORMED = 'MALFORMED'
SIG_INVALID = 'INVALID'
SIG_NONE = 'NONE'
SIG_PRESENT = 'PRESENT'
SIG_NOTPE = 'N/A'
SIG_ERROR = 'ERROR'

SIG_BAD_STATUSES = (SIG_TAMPERED, SIG_UNTRUSTED, SIG_EXPIRED, SIG_MALFORMED, SIG_INVALID)

VERIFY_MODES = ('any', 'first', 'all', 'best')
DEFAULT_VERIFY_MODE = 'best'

_DIGEST_RANK = {'MD5': 1, 'SHA1': 2, 'SHA224': 3, 'SHA256': 4, 'SHA384': 5, 'SHA512': 6}

_SECURITY_DIRECTORY = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']

_RESULT_MAP = {
    'OK': SIG_VALID,
    'NOT_SIGNED': SIG_NONE,
    'INVALID_DIGEST': SIG_TAMPERED,
    'INVALID_ADDITIONAL_HASH': SIG_TAMPERED,
    'INCONSISTENT_DIGEST_ALGORITHM': SIG_INVALID,
    'PARSE_ERROR': SIG_MALFORMED,
    'CERTIFICATE_ERROR': SIG_UNTRUSTED,
    'COUNTERSIGNER_ERROR': SIG_UNTRUSTED,
    'VERIFY_ERROR': SIG_INVALID,
    'UNKNOWN_ERROR': SIG_INVALID,
}

_EXPIRED_MARKERS = ('expired', 'not valid at', 'validity period')


def signify_available():
    try:
        import signify.authenticode  # noqa: F401
        return True
    except Exception:
        return False


def has_embedded_signature(file_item):
    try:
        pe = pefile.PE(file_item, fast_load=True)
    except Exception:
        return None
    try:
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_SECURITY_DIRECTORY]
        return bool(directory.VirtualAddress and directory.Size)
    except Exception:
        return None
    finally:
        try:
            pe.close()
        except Exception:
            pass


def _blank_record(status, detail=''):
    return {
        'status': status,
        'signer': '',
        'issuer': '',
        'valid_from': '',
        'valid_to': '',
        'timestamp': '',
        'algorithm': '',
        'thumbprint': '',
        'serial_number': '',
        'count': 0,
        'primary_index': 0,
        'signatures': [],
        'detail': detail,
    }


def _safe_text(getter):
    try:
        value = getter()
    except Exception:
        return ''
    return '' if value is None else strip_terminal_escapes(str(value))


def _signer_certificate(signature):
    info = signature.signer_info
    for certificate in signature.certificates:
        if certificate.serial_number == info.serial_number and certificate.issuer == info.issuer:
            return certificate
    return None


def _digest_algorithm(signer_info):
    name = _safe_text(lambda: signer_info.digest_algorithm.__name__)
    if not name:
        name = _safe_text(lambda: signer_info.digest_algorithm.name)
    return name.replace('openssl_', '').replace('_', '-').upper()


def _describe_signature(signature):
    entry = {
        'signer': '',
        'issuer': '',
        'valid_from': '',
        'valid_to': '',
        'timestamp': '',
        'algorithm': '',
        'thumbprint': '',
        'serial_number': '',
    }

    entry['algorithm'] = _digest_algorithm(signature.signer_info)

    try:
        certificate = _signer_certificate(signature)
    except Exception:
        certificate = None

    if certificate is not None:
        entry['signer'] = _safe_text(lambda: certificate.subject.dn)
        entry['issuer'] = _safe_text(lambda: certificate.issuer.dn)
        entry['valid_from'] = _safe_text(lambda: certificate.valid_from)
        entry['valid_to'] = _safe_text(lambda: certificate.valid_to)
        entry['thumbprint'] = _safe_text(lambda: certificate.sha1_fingerprint).upper()
        entry['serial_number'] = _safe_text(lambda: '%x' % certificate.serial_number).upper()

    try:
        countersigner = signature.signer_info.countersigner
        signing_time = getattr(countersigner, 'signing_time', None) or signature.signer_info.signing_time
        if signing_time:
            entry['timestamp'] = str(signing_time)
    except Exception:
        pass

    return entry


def is_weak_digest(algorithm):
    rank = _DIGEST_RANK.get(str(algorithm).upper(), 0)
    return 0 < rank <= _DIGEST_RANK['SHA1']


def _primary_index(entries, verify_mode):
    if verify_mode != 'best' or len(entries) < 2:
        return 0

    primary = 0
    for index in range(1, len(entries)):
        if _DIGEST_RANK.get(entries[index]['algorithm'], 0) > _DIGEST_RANK.get(entries[primary]['algorithm'], 0):
            primary = index
    return primary


def _describe_signatures(record, authenticode, verify_mode):
    entries = []
    try:
        for signature in authenticode.iter_embedded_signatures():
            entries.append(_describe_signature(signature))
    except Exception:
        pass

    if not entries:
        return

    primary = _primary_index(entries, verify_mode)
    record['signatures'] = entries
    record['count'] = len(entries)
    record['primary_index'] = primary
    for field in ('signer', 'issuer', 'valid_from', 'valid_to', 'timestamp',
                  'algorithm', 'thumbprint', 'serial_number'):
        record[field] = entries[primary][field]


def signature_info(file_item, verify=True, verify_mode=DEFAULT_VERIFY_MODE):
    presence = has_embedded_signature(file_item)

    if presence is None:
        return _blank_record(SIG_NOTPE, 'Not a PE file.')

    if not verify or not signify_available():
        if presence:
            return _blank_record(
                SIG_PRESENT,
                'An embedded signature is present. Install malwoverview[signature] to verify it.'
            )
        return _blank_record(SIG_NONE, 'No embedded signature.')

    try:
        from signify.authenticode import AuthenticodeFile
    except Exception as e:
        return _blank_record(SIG_ERROR, 'The signify package could not be loaded: %s' % str(e))

    if verify_mode not in VERIFY_MODES:
        verify_mode = DEFAULT_VERIFY_MODE

    try:
        with open(file_item, 'rb') as handle:
            authenticode = AuthenticodeFile.from_stream(handle)
            result, error = authenticode.explain_verify(signature_types='embedded',
                                                        multi_verify_mode=verify_mode)
            status = _RESULT_MAP.get(getattr(result, 'name', ''), SIG_INVALID)
            detail = strip_terminal_escapes(str(error)) if error else ''

            if status == SIG_UNTRUSTED and detail:
                lowered = detail.lower()
                if any(marker in lowered for marker in _EXPIRED_MARKERS):
                    status = SIG_EXPIRED

            record = _blank_record(status, detail)

            if status != SIG_NONE:
                _describe_signatures(record, authenticode, verify_mode)

            return record
    except Exception as e:
        return _blank_record(SIG_ERROR, strip_terminal_escapes('%s: %s' % (type(e).__name__, str(e))))


def certificate_expired(valid_to):
    if not valid_to:
        return False
    try:
        from datetime import datetime, timezone
        expiry = datetime.fromisoformat(str(valid_to))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry < datetime.now(timezone.utc)
    except Exception:
        return False


def signature_summary(records):
    counts = {}
    for record in records:
        status = record.get('signature_status', SIG_NOTPE)
        counts[status] = counts.get(status, 0) + 1
    return counts


def unavailable_notice():
    return ("Signature verification needs the signify package. "
            "Install it with: pip install malwoverview[signature]")


def basename(file_item):
    return os.path.basename(file_item)
