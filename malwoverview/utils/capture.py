import builtins
import sys
import threading
from io import StringIO


class CapturedExit(Exception):
    pass


_CAPTURE_LOCK = threading.Lock()


class _Tee:
    def __init__(self, primary, secondary):
        self.primary = primary
        self.secondary = secondary

    def write(self, data):
        self.primary.write(data)
        self.secondary.write(data)

    def flush(self):
        self.primary.flush()
        self.secondary.flush()

    def __getattr__(self, name):
        return getattr(self.__dict__['primary'], name)


def run_captured(func, *args, _tee=False, **kwargs):
    def _fake_exit(code=0):
        raise CapturedExit()

    with _CAPTURE_LOCK:
        buf = StringIO()
        orig_stdout = sys.stdout
        orig_exit = builtins.exit
        orig_quit = builtins.quit
        orig_sys_exit = sys.exit
        builtins.exit = _fake_exit
        builtins.quit = _fake_exit
        sys.exit = _fake_exit
        sys.stdout = _Tee(orig_stdout, buf) if _tee else buf
        try:
            func(*args, **kwargs)
            return True, buf.getvalue(), None
        except CapturedExit:
            return True, buf.getvalue(), None
        except Exception as e:
            return False, buf.getvalue(), e
        finally:
            sys.stdout = orig_stdout
            builtins.exit = orig_exit
            builtins.quit = orig_quit
            sys.exit = orig_sys_exit
