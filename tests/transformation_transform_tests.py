from nose.tools import *

from wirecaml.extraction import cfg
from wirecaml.transformation import transform


def setup():
    pass


def teardown():
    pass


def test_transform_graph():
    filename = "tests/examples/CWE_89__GET__no_sanitizing__multiple_AS-concatenation.php"
    g = cfg.create_graph("tests/examples", filename)
    flaw_dict = {filename: [52]}

    df = transform.transform_graph(g, flaw_dict, mark_whole_path=False)
    assert (set(df.loc[df.vulnerable == 1].line) == {62})
    df = transform.transform_graph(g, flaw_dict, mark_whole_path=True)
    assert(set(df.loc[df.vulnerable == 1].line) == {52, 62})

    flaw_dict = {filename: [49]}
    df = transform.transform_graph(g, flaw_dict, mark_whole_path=True)
    # TODO: Parse variable assignment (line 59) in while statement
    # assert (set(df.loc[df.vulnerable == 1].line) == {49, 54, 56, 58, 59})


def test_transform_graph_addslashes():
    filename = "tests/examples/CWE_89__array-GET__func_addslashes__select_from-interpretation_simple_quote.php"
    g = cfg.create_graph("tests/examples", filename)
    flaw_dict = {}

    df = transform.transform_graph(g, flaw_dict, mark_whole_path=True)
    assert_equal(set(df.loc[df.line == 59].func_addslashes), {1.0})


def test_transform_graph_tainted():
    filename = "tests/examples/CWE_89__GET__no_sanitizing__multiple_AS-concatenation.php"
    g = cfg.create_graph("tests/examples", filename)
    flaw_dict = {filename: [52]}

    df = transform.transform_graph(g, flaw_dict, mark_whole_path=False)
    assert (set(df.loc[df.vulnerable == 1].line) == {62})
    df = transform.transform_graph(g, flaw_dict, mark_whole_path=True)
    assert(set(df.loc[df.vulnerable == 1].line) == {52, 62})
    assert(set(df.loc[df.vulnerable == 1].tainted) == {1})


def test_transform_graph_not_tainted():
    filename = "tests/examples/CWE_89__GET__CAST-cast_int__multiple_AS-interpretation_simple_quote.php"
    flaw_dict = {}

    g = cfg.create_graph("tests/examples", filename)

    df = transform.transform_graph(g, {}, mark_whole_path=True)
    assert_equal(set(df.loc[df.line == 53].tainted), {0})


def test_recursion_loop():
    filename = "tests/examples/test_foreach_loop.php"
    flaw_dict = {}

    g = cfg.create_graph("tests/examples", filename)

    from wirecaml.tools import config
    config.init(config_filename='config.ini')

    cfg.create_png(g)

    df = transform.transform_graph(g, {}, mark_whole_path=True)


# def test_create_png():
#      g = cfg.create_graph("tests/examples", "tests/examples/function_example.php")
#
#      from wirecaml.tools import config
#      config.init(config_filename='config.ini')
#
#      cfg.create_png(g)

# def test_create_csv():
#     filename = "tests/examples/function_example.php"
#     flaw_dict = {filename: [6]}
#
#     g = cfg.create_graph("tests/examples", filename)
#
#     df = transform.transform_graph(g, flaw_dict, mark_whole_path=True)
#
#     df.to_csv('D:/thesis-data/graphs/table.csv')


