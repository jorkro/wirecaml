from nose.tools import *
import networkx as nx

from phply.phplex import lexer
from phply.phpparse import make_parser

from wirecaml.extraction.code_node import Tainted
from wirecaml.extraction.my_php_listener import MyPHPListener
from wirecaml.extraction.phptraverser import php_traverser


def get_listener(code, fake_filename='filename.php'):
    parser = make_parser()

    line_map = [(None, None), ('filename.php', 1)]

    nodes = parser.parse(code, lexer=lexer.clone(), tracking=True, debug=False)
    listener = MyPHPListener(line_map=line_map, name=fake_filename)
    php_traverser.traverse(nodes, listener)

    return listener


def setup():
    pass


def teardown():
    pass


def test_echo():
    code = '<?php echo "teststring";'

    G = get_listener(code).get_graph()

    assert_equal(G.number_of_edges(), 0)
    assert_equal(G.number_of_nodes(), 1)

    n = G.nodes()[0]

    assert_equal(n.stmt, 'echo')
    assert_equal(n.line, 1)
    assert_equal(n.text, "echo 'teststring'")


def test_if():
    code = '<?php if ($a) { foo(); }'

    G = get_listener(code).get_graph()

    assert(G.number_of_edges() == 3)
    assert(G.number_of_nodes() == 3)

    root = nx.topological_sort(G)[0]

    assert(root.stmt == 'if')

    neighbors = G.neighbors(root)

    assert(neighbors[0].stmt == 'foo()' or neighbors[1].stmt == 'foo()')


def test_if_assignment():
    code = '<?php if ($a = 3) { }'

    G = get_listener(code).get_graph()

    root = nx.topological_sort(G)[0]

    assert (root.stmt == 'if')


def test_while():
    code = '<?php while(true) { foo(); bar(); }'

    G = get_listener(code).get_graph()

    assert(G.number_of_nodes() == 4)
    assert(G.number_of_edges() == 5)

    while_node = [n for n in G.nodes() if n.stmt == 'while'][0]
    assert while_node

    exit_node = [n for n in G.nodes() if n.stmt == 'empty'][0]
    assert exit_node
    assert(exit_node in G.neighbors(while_node))

    other_neighbor = [n for n in G.neighbors(while_node) if n != exit_node][0]

    assert(other_neighbor.stmt == 'foo()')


def test_while_assignment():
    code = '<?php while($a = foo()) { bar(); }'

    G = get_listener(code).get_graph()

    while_node = [n for n in G.nodes() if n.stmt == 'while'][0]
    assert_equal(while_node.tainted, Tainted.MAYBE_TAINTED)


def test_assignment():
    code = '<?php $a = 3;'

    G = get_listener(code).get_graph()

    assert (G.number_of_edges() == 0)
    assert (G.number_of_nodes() == 1)

    n = G.nodes()[0]
    assert_equal(n.tainted, Tainted.NOT_TAINTED)


def test_function():
    code = '<?php function foobar() { echo "Hello"; }; foobar(); echo "The end";'

    G = get_listener(code).get_graph()

    assert_equal(G.number_of_edges(), 3)
    assert_equal(G.number_of_nodes(), 3)


def test_assignment_tainted():
    code = '<?php $a = $_GET["foobar"];'

    G = get_listener(code).get_graph()

    n = G.nodes()[0]
    assert_equal(n.tainted, Tainted.MAYBE_TAINTED)


def test_assignment_tainted_cast():
    code = '<?php $tainted = (float) $_GET["foobar"];'

    G = get_listener(code).get_graph()

    n = G.nodes()[0]
    assert_equal(n.tainted, Tainted.NOT_TAINTED)


def test_assignment_tainted_arithmetic_1():
    code = '<?php $tainted = $_GET["foobar"] + 0;'

    G = get_listener(code).get_graph()

    n = G.nodes()[0]
    assert_equal(n.tainted, Tainted.NOT_TAINTED)


def test_assignment_tainted_arithmetic_2():
    code = '<?php $tainted = $_GET["foobar"]; $tainted += 0;'

    G = get_listener(code).get_graph()

    n1 = G.nodes()[0]
    n2 = G.nodes()[1]
    assert ((n1.tainted == Tainted.NOT_TAINTED or n2.tainted == Tainted.MAYBE_TAINTED) or
            (n1.tainted == Tainted.MAYBE_TAINTED or n2.tainted == Tainted.NOT_TAINTED))


def test_assignment_tainted_floatval():
    code = '<?php $tainted = floatval($_GET["userData"]);'

    G = get_listener(code).get_graph()

    n = G.nodes()[0]
    assert_equal(n.tainted, Tainted.NOT_TAINTED)


def test_assignment_tainted_intval():
    code = '<?php $tainted = intval($_GET["userData"]);'

    G = get_listener(code).get_graph()

    n = G.nodes()[0]
    assert_equal(n.tainted, Tainted.NOT_TAINTED)


def test_assignment_tainted_indirect():
    code = '<?php $tainted = $_GET["userData"]; $a = $tainted . "foobar";'

    G = get_listener(code).get_graph()

    n1 = G.nodes()[0]
    n2 = G.nodes()[1]
    assert (n1.is_tainted() and n2.is_tainted())


def test_assignment_tainted_ternary():
    code = '<?php $tainted = $_POST["UserData"]; $tainted = $tainted == "safe1" ? "safe1": "safe2";'

    G = get_listener(code).get_graph()

    n1 = G.nodes()[0]
    n2 = G.nodes()[1]
    assert ((n1.is_tainted() and not n2.is_tainted()) or (not n1.is_tainted() and n2.is_tainted()))


def test_assignment_tainted_if():
    code = '<?php $handle = @fopen("/tmp/tainted.txt", "r"); ' \
           '$tainted = "";' \
           'if (($tainted = fgets($handle, 4096)) == false) {' \
           '$tainted = "";' \
           '}' \
           'fclose($handle);' \
           '$query = "SELECT * FROM \' $tainted \'";' \
           '$res = mysql_query($query); // execution'

    G = get_listener(code).get_graph()

    if_node = [n for n in G.nodes() if n.stmt == 'if'][0]

    last_node = [n for n in G.nodes() if 'mysql_query' in n.stmt_funcs][0]
    assert(if_node.is_tainted())
    assert(last_node.is_tainted())


def test_assignment_tainted_if_2():
    code = '<?php $handle = @fopen("/tmp/tainted.txt", "r");' \
           'if ($handle) {' \
           'if(($tainted = fgets($handle, 4096)) == false) {' \
           '$tainted = "1";' \
           '}' \
           'fclose($handle);' \
           '} else {' \
           '$tainted = "2";' \
           '}' \
           '$sanitized = filter_var($tainted, FILTER_SANITIZE_SPECIAL_CHARS);' \
           '$tainted = $sanitized ;' \
           '$query = sprintf("SELECT * FROM \'%s\'", $tainted);' \
           '$conn = mysql_connect(\'localhost\', \'mysql_user\', \'mysql_password\');' \
           'mysql_select_db(\'dbname\') ;' \
           'echo "query : ". $query ."<br /><br />" ;' \
           '$res = mysql_query($query); //execution'

    G = get_listener(code).get_graph()

    last_node = [n for n in G.nodes() if 'mysql_query' in n.stmt_funcs][0]
    assert(last_node.is_tainted())


def test_assignment_not_tainted_echo():
    code = '<?php echo "foobar";'

    G = get_listener(code).get_graph()

    n1 = G.nodes()[0]

    assert (not n1.is_tainted())