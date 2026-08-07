import shutil
import subprocess
import sys

try:
    import pyperclip
    _HAS_PYPERCLIP = True
except ImportError:
    _HAS_PYPERCLIP = False


CF_UNICODETEXT = 13
READ_TIMEOUT = 5

POSIX_READERS = (
    ('pbpaste',),
    ('wl-paste', '--no-newline'),
    ('xclip', '-selection', 'clipboard', '-o'),
    ('xsel', '--clipboard', '--output'),
)

EMPTY = "the clipboard is empty or holds no text"


def _read_windows():
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL

    if not user32.OpenClipboard(None):
        return None, "the clipboard is held by another application"
    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return None, EMPTY
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            return None, "the clipboard contents could not be locked for reading"
        try:
            return ctypes.c_wchar_p(pointer).value, None
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _read_posix():
    missing = []
    failures = []
    for command in POSIX_READERS:
        if shutil.which(command[0]) is None:
            missing.append(command[0])
            continue
        try:
            done = subprocess.run(command, capture_output=True, timeout=READ_TIMEOUT)
        except subprocess.TimeoutExpired:
            failures.append("%s timed out" % command[0])
            continue
        except OSError as error:
            failures.append("%s failed (%s)" % (command[0], error))
            continue
        if done.returncode != 0:
            detail = done.stderr.decode('utf-8', 'replace').strip().splitlines()
            failures.append("%s exited %d%s" % (
                command[0], done.returncode, ": " + detail[0] if detail else ""))
            continue
        return done.stdout.decode('utf-8', 'replace'), None

    if failures:
        return None, "; ".join(failures)
    return None, ("no clipboard tool found - install one of: %s"
                  % ", ".join(name for name in missing))


def read_clipboard():
    try:
        if sys.platform == 'win32':
            text, error = _read_windows()
        else:
            text, error = _read_posix()
    except Exception as read_error:
        text = None
        error = "clipboard read failed (%s: %s)" % (type(read_error).__name__, read_error)

    if text:
        return text, None

    if _HAS_PYPERCLIP:
        try:
            fallback = pyperclip.paste()
        except Exception as pyperclip_error:
            return None, "%s; pyperclip also failed (%s)" % (error, pyperclip_error)
        if fallback:
            return fallback, None
        if error is None:
            error = EMPTY

    return None, error or EMPTY
