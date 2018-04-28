import datetime


# Got this from https://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python
class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Level:
    WARNING = Color.WARNING + '[WARNING] ' + Color.ENDC
    NOTICE = '[NOTICE] '
    ERROR = Color.FAIL + '[ERROR] ' + Color.ENDC


def print_banner(text):
    l = len(text) + 4

    print()
    print(Color.BOLD + '=' * l + Color.ENDC)
    print(Color.BOLD + "| %s |" % text + Color.ENDC)
    print(Color.BOLD + '=' * l + Color.ENDC)


def print_warning(text):
    print_text(Level.WARNING, text)


def print_notice(text):
    print_text(Level.NOTICE, text)


def print_error(text):
    print_text(Level.ERROR, text)


def print_text(lvl, text):
    lines = text.splitlines()
    time = datetime.datetime.now().strftime('%H:%M:%S')

    for line in lines:
        print('%s %s%s' % (time, lvl, line))


