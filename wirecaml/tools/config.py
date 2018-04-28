import configparser
import ast

from wirecaml.tools.ascii import print_error

config = None


def init(config_filename='config.ini'):
    global config

    if config is None:
        config = configparser.RawConfigParser()
        config.read(config_filename)


def get(section, name, optional=False):
    try:
        return config.get(section, name)
    except configparser.NoOptionError:
        if optional:
            return None

        print_error("Missing required option '%s' under section '%s'" % (name, section))
        exit(0)


def get_str(section, name):
    return str(get(section, name))


def get_int(section, name):
    return int(get(section, name))


def get_float(section, name):
    return float(get(section, name))


def get_list(section, name):
    return get(section, name).split(',')


def get_dict(section, name, optional=False):
    v = get(section, name, optional)

    if v is None:
        return None

    return ast.literal_eval(v)


# Returns a list of tuples
def get_items(section):
    return config.items(section)


def get_boolean(section, name):
    t = str(get(section, name))

    for match in ['true', '1', 'yes', 'on']:
        if match.lower() == t.lower():
            return True

    return False


def set(section, name, value):
    config.set(section, name, value)
