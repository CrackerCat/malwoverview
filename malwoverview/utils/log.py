import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors


def debug(msg):
    if cv.verbosity >= 1:
        print(mycolors.foreground.neutral(cv.bkg) + "[DEBUG] " + str(msg) + mycolors.reset)


def info(msg):
    if cv.verbosity >= 0:
        print(str(msg))


def warn(msg):
    print(mycolors.foreground.warning(cv.bkg) + "[WARN] " + str(msg) + mycolors.reset)
